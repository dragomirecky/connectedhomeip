/*
 * Copyright (c) 2025 Ulliso
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Platform mDNS implementation for Zephyr.
 *
 * Bridges CHIP's DNS-SD platform API to Zephyr's native mDNS responder
 * and DNS-SD service registration. Uses mdns_responder_set_ext_records()
 * for runtime service advertisement.
 *
 * Publishing is fully supported (commissionable + operational services).
 * Browse/resolve are not implemented — a Matter device only needs to
 * advertise; the commissioner handles discovery.
 */

#include <lib/dnssd/platform/Dnssd.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/CHIPDeviceLayer.h>

#include <inet/UDPEndPointImpl.h>
#include <platform/Zephyr/InetUtils.h>

extern "C" {
#include <zephyr/net/dns_sd.h>
#include <zephyr/net/hostname.h>
#include <zephyr/net/net_if.h>
#ifdef CONFIG_MDNS_RESPONDER
#include <zephyr/net/mdns_responder.h>
#endif
}

#include <cstring>
#include <algorithm>

namespace chip {
namespace Dnssd {

namespace {

/* Maximum number of concurrent DNS-SD service records. Matter typically
 * publishes 2-3 services: _matterc._udp (commissionable), _matter._tcp
 * (operational), and optionally _matterc._udp subtypes. */
static constexpr size_t kMaxServices = 6;

/* Maximum TXT record size per RFC 6763 (we encode all key=value pairs
 * into a single buffer with length-prefix encoding). */
static constexpr size_t kMaxTxtSize = 512;

/* Maximum instance name length (RFC 6763 Section 7.2). */
static constexpr size_t kMaxInstanceLen = 63;

/* Maximum service name length including underscore. */
static constexpr size_t kMaxServiceLen = DNS_SD_SERVICE_MAX_SIZE;

struct ServiceRecord
{
    char instance[kMaxInstanceLen + 1];
    char service[kMaxServiceLen + 1];
    char proto[5]; /* "_tcp" or "_udp" */
    char txt[kMaxTxtSize];
    size_t txtSize;
    uint16_t portBe; /* Port in big-endian (network byte order) */
    bool active;
};

static ServiceRecord sServices[kMaxServices];
static dns_sd_rec sExtRecords[kMaxServices];
static size_t sActiveCount = 0;
static bool sInitialized   = false;

static DnssdAsyncReturnCallback sErrorCallback = nullptr;
static void * sErrorContext                    = nullptr;

/* ------------------------------------------------------------------ */
/* Lightweight mDNS query responder using CHIP's UDP endpoints.       */
/* Zephyr's built-in mDNS responder uses a socket service that may    */
/* not work on virtual network interfaces (Renode TAP bridge).  This  */
/* responder uses CHIP's UDPEndPoint which is known to work.          */
/* ------------------------------------------------------------------ */
static chip::Inet::UDPEndPointHandle sMdnsEndpoint4;

/* DNS wire-format helpers */
static size_t WriteDnsName(uint8_t * buf, size_t maxLen, const char * labels[], size_t labelCount)
{
    size_t pos = 0;
    for (size_t i = 0; i < labelCount; i++)
    {
        size_t len = strlen(labels[i]);
        if (pos + 1 + len >= maxLen) return 0;
        buf[pos++] = static_cast<uint8_t>(len);
        memcpy(&buf[pos], labels[i], len);
        pos += len;
    }
    if (pos < maxLen) buf[pos++] = 0;
    return pos;
}

static void HandleMdnsQuery(chip::Inet::UDPEndPoint * endPoint, chip::System::PacketBufferHandle && buffer,
                             const chip::Inet::IPPacketInfo * pktInfo)
{
    if (buffer->DataLength() < 12) return;

    const uint8_t * query = buffer->Start();
    uint16_t flags = (query[2] << 8) | query[3];
    if (flags & 0x8000) return; /* Not a query */

    /* Check if query contains any of our service types */
    ServiceRecord * match = nullptr;
    for (size_t i = 0; i < kMaxServices; i++)
    {
        if (!sServices[i].active) continue;
        /* Simple substring search in the raw query for service name */
        const char * svc = sServices[i].service + 1; /* skip leading underscore for search */
        size_t svcLen = strlen(svc);
        for (size_t j = 12; j + svcLen < buffer->DataLength(); j++)
        {
            if (memcmp(&query[j], svc, svcLen) == 0)
            {
                match = &sServices[i];
                break;
            }
        }
        if (match) break;
    }

    if (!match) return;

    /* Get our IPv4 address for the A record */
    struct net_if * iface = DeviceLayer::InetUtils::GetWiFiInterface();
    if (!iface) iface = net_if_get_default();
    if (!iface) return;

    struct net_if_addr * unicast = NULL;
    struct net_if_ipv4 * ipv4 = iface->config.ip.ipv4;
    if (!ipv4) return;
    for (int i = 0; i < NET_IF_MAX_IPV4_ADDR; i++)
    {
        if (ipv4->unicast[i].ipv4.is_used &&
            ipv4->unicast[i].ipv4.address.family == AF_INET)
        {
            unicast = &ipv4->unicast[i].ipv4;
            break;
        }
    }
    if (!unicast) return;

    uint32_t ip4addr = unicast->address.in_addr.s_addr;
    uint16_t port = ntohs(match->portBe);

    /* Build mDNS response */
    uint8_t resp[512];
    size_t pos = 0;

    /* Header */
    resp[pos++] = query[0]; resp[pos++] = query[1]; /* Transaction ID */
    resp[pos++] = 0x84; resp[pos++] = 0x00; /* Flags: response, authoritative */
    resp[pos++] = 0x00; resp[pos++] = 0x00; /* Questions: 0 */
    resp[pos++] = 0x00; resp[pos++] = 0x01; /* Answers: 1 (PTR) */
    resp[pos++] = 0x00; resp[pos++] = 0x00; /* Authority: 0 */
    resp[pos++] = 0x00; resp[pos++] = 0x03; /* Additional: 3 (SRV + TXT + A) */

    /* Answer: PTR record for _service._proto.local -> instance._service._proto.local */
    const char * ptrLabels[] = { match->service, match->proto, "local" };
    pos += WriteDnsName(&resp[pos], sizeof(resp) - pos, ptrLabels, 3);
    resp[pos++] = 0x00; resp[pos++] = 0x0C; /* Type: PTR */
    resp[pos++] = 0x00; resp[pos++] = 0x01; /* Class: IN */
    resp[pos++] = 0x00; resp[pos++] = 0x00; resp[pos++] = 0x00; resp[pos++] = 0x78; /* TTL: 120 */
    /* PTR target (instance._service._proto.local) */
    const char * instLabels[] = { match->instance, match->service, match->proto, "local" };
    uint8_t instName[128];
    size_t instNameLen = WriteDnsName(instName, sizeof(instName), instLabels, 4);
    resp[pos++] = (instNameLen >> 8) & 0xFF; resp[pos++] = instNameLen & 0xFF;
    size_t instNamePos = pos;
    memcpy(&resp[pos], instName, instNameLen);
    pos += instNameLen;

    /* Additional 1: SRV record */
    /* Use name compression pointer to instName */
    resp[pos++] = 0xC0 | ((instNamePos >> 8) & 0x3F); resp[pos++] = instNamePos & 0xFF;
    resp[pos++] = 0x00; resp[pos++] = 0x21; /* Type: SRV */
    resp[pos++] = 0x80; resp[pos++] = 0x01; /* Class: IN, cache-flush */
    resp[pos++] = 0x00; resp[pos++] = 0x00; resp[pos++] = 0x00; resp[pos++] = 0x78; /* TTL: 120 */
    /* SRV data: priority(2) + weight(2) + port(2) + target hostname */
    char hostname[64];
    snprintf(hostname, sizeof(hostname), "%s", net_hostname_get());
    const char * hostLabels[] = { hostname, "local" };
    uint8_t hostName[128];
    size_t hostNameLen = WriteDnsName(hostName, sizeof(hostName), hostLabels, 2);
    uint16_t srvDataLen = 6 + hostNameLen;
    resp[pos++] = (srvDataLen >> 8) & 0xFF; resp[pos++] = srvDataLen & 0xFF;
    resp[pos++] = 0x00; resp[pos++] = 0x00; /* Priority: 0 */
    resp[pos++] = 0x00; resp[pos++] = 0x00; /* Weight: 0 */
    resp[pos++] = (port >> 8) & 0xFF; resp[pos++] = port & 0xFF;
    size_t hostNamePos = pos;
    memcpy(&resp[pos], hostName, hostNameLen);
    pos += hostNameLen;

    /* Additional 2: TXT record */
    resp[pos++] = 0xC0 | ((instNamePos >> 8) & 0x3F); resp[pos++] = instNamePos & 0xFF;
    resp[pos++] = 0x00; resp[pos++] = 0x10; /* Type: TXT */
    resp[pos++] = 0x80; resp[pos++] = 0x01; /* Class: IN, cache-flush */
    resp[pos++] = 0x00; resp[pos++] = 0x00; resp[pos++] = 0x00; resp[pos++] = 0x78; /* TTL: 120 */
    uint16_t txtLen = (match->txtSize > 0) ? match->txtSize : 1;
    resp[pos++] = (txtLen >> 8) & 0xFF; resp[pos++] = txtLen & 0xFF;
    if (match->txtSize > 0)
    {
        memcpy(&resp[pos], match->txt, match->txtSize);
        pos += match->txtSize;
    }
    else
    {
        resp[pos++] = 0; /* Empty TXT */
    }

    /* Additional 3: A record for hostname */
    resp[pos++] = 0xC0 | ((hostNamePos >> 8) & 0x3F); resp[pos++] = hostNamePos & 0xFF;
    resp[pos++] = 0x00; resp[pos++] = 0x01; /* Type: A */
    resp[pos++] = 0x80; resp[pos++] = 0x01; /* Class: IN, cache-flush */
    resp[pos++] = 0x00; resp[pos++] = 0x00; resp[pos++] = 0x00; resp[pos++] = 0x78; /* TTL: 120 */
    resp[pos++] = 0x00; resp[pos++] = 0x04; /* Data length: 4 */
    memcpy(&resp[pos], &ip4addr, 4);
    pos += 4;

    /* Send response as multicast */
    auto respBuf = chip::System::PacketBufferHandle::NewWithData(resp, pos);
    if (respBuf.IsNull()) return;

    chip::Inet::IPAddress mcastAddr;
    chip::Inet::IPAddress::FromString("224.0.0.251", mcastAddr);
    endPoint->SendTo(mcastAddr, 5353, std::move(respBuf), pktInfo->Interface);
}

static CHIP_ERROR StartMdnsListener()
{
    auto * udpManager = chip::DeviceLayer::UDPEndPointManager();
    VerifyOrReturnError(udpManager != nullptr, CHIP_ERROR_INCORRECT_STATE);

    ReturnErrorOnFailure(udpManager->NewEndPoint(sMdnsEndpoint4));

    ReturnErrorOnFailure(sMdnsEndpoint4->Bind(chip::Inet::IPAddressType::kIPv4, chip::Inet::IPAddress::Any, 5353,
                                               chip::Inet::InterfaceId::Null()));
    ReturnErrorOnFailure(sMdnsEndpoint4->Listen(HandleMdnsQuery, nullptr /* onError */, nullptr /* appState */));

    /* Join mDNS multicast group */
    chip::Inet::IPAddress mdnsMcast;
    chip::Inet::IPAddress::FromString("224.0.0.251", mdnsMcast);
    sMdnsEndpoint4->JoinMulticastGroup(chip::Inet::InterfaceId::Null(), mdnsMcast);

    ChipLogProgress(DeviceLayer, "mDNS: UDP query listener started on port 5353");
    return CHIP_NO_ERROR;
}

/**
 * Encode CHIP TextEntry array into RFC 6763 TXT wire format.
 *
 * Each entry is encoded as: <length_byte><key>=<value>
 * Entries without data are encoded as: <length_byte><key>
 */
static size_t EncodeTxtRecords(const TextEntry * entries, size_t count, char * buf, size_t bufSize)
{
    size_t offset = 0;

    for (size_t i = 0; i < count; i++)
    {
        const TextEntry & entry = entries[i];
        size_t keyLen           = strlen(entry.mKey);
        size_t entryLen         = keyLen;

        if (entry.mData != nullptr && entry.mDataSize > 0)
        {
            entryLen += 1 + entry.mDataSize; /* +1 for '=' */
        }

        /* RFC 6763: each entry is at most 255 bytes */
        if (entryLen > 255)
        {
            ChipLogError(DeviceLayer, "mDNS TXT entry '%s' too long (%u bytes)", entry.mKey, static_cast<unsigned>(entryLen));
            continue;
        }

        /* Check we have room for length byte + entry */
        if (offset + 1 + entryLen > bufSize)
        {
            ChipLogError(DeviceLayer, "mDNS TXT buffer full, dropping remaining entries");
            break;
        }

        /* Length byte */
        buf[offset++] = static_cast<char>(entryLen);

        /* Key */
        memcpy(&buf[offset], entry.mKey, keyLen);
        offset += keyLen;

        /* =Value (if present) */
        if (entry.mData != nullptr && entry.mDataSize > 0)
        {
            buf[offset++] = '=';
            memcpy(&buf[offset], entry.mData, entry.mDataSize);
            offset += entry.mDataSize;
        }
    }

    return offset;
}

/**
 * Rebuild the external records array and register with Zephyr's mDNS responder.
 */
static void UpdateExtRecords()
{
    size_t count = 0;

    for (size_t i = 0; i < kMaxServices && count < kMaxServices; i++)
    {
        if (!sServices[i].active)
        {
            continue;
        }

        dns_sd_rec & rec = sExtRecords[count];
        rec.instance     = sServices[i].instance;
        rec.service      = sServices[i].service;
        rec.proto        = sServices[i].proto;
        rec.domain       = "local";
        rec.text         = sServices[i].txt;
        rec.text_size    = sServices[i].txtSize;
        rec.port         = &sServices[i].portBe;
        count++;
    }

    sActiveCount = count;

    if (count > 0)
    {
#ifdef CONFIG_MDNS_RESPONDER
        int rc = mdns_responder_set_ext_records(sExtRecords, count);
        if (rc != 0)
        {
            ChipLogError(DeviceLayer, "mdns_responder_set_ext_records failed: %d", rc);
        }
#endif
        ChipLogProgress(DeviceLayer, "mDNS: registered %u service(s)", static_cast<unsigned>(count));
    }
    else
    {
#ifdef CONFIG_MDNS_RESPONDER
        mdns_responder_set_ext_records(nullptr, 0);
#endif
        ChipLogProgress(DeviceLayer, "mDNS: all services removed");
    }
}

/**
 * Find an existing service record by type+protocol+name, or allocate a free slot.
 */
static ServiceRecord * FindOrAllocate(const char * type, const char * proto, const char * name)
{
    /* First, look for an existing record with the same type+proto+name */
    for (size_t i = 0; i < kMaxServices; i++)
    {
        if (sServices[i].active && strcmp(sServices[i].service, type) == 0 && strcmp(sServices[i].proto, proto) == 0 &&
            strcmp(sServices[i].instance, name) == 0)
        {
            return &sServices[i];
        }
    }

    /* Allocate a free slot */
    for (size_t i = 0; i < kMaxServices; i++)
    {
        if (!sServices[i].active)
        {
            return &sServices[i];
        }
    }

    return nullptr;
}

} /* anonymous namespace */

CHIP_ERROR ChipDnssdInit(DnssdAsyncReturnCallback initCallback, DnssdAsyncReturnCallback errorCallback, void * context)
{
    sErrorCallback = errorCallback;
    sErrorContext  = context;
    sInitialized   = true;

    /* Clear all service records */
    memset(sServices, 0, sizeof(sServices));
    sActiveCount = 0;

    /* Start our own mDNS query listener using CHIP's UDP endpoints.
     * This complements Zephyr's built-in mDNS responder and ensures
     * queries are handled on virtual network interfaces (Renode TAP). */
    CHIP_ERROR listenerErr = StartMdnsListener();
    if (listenerErr != CHIP_NO_ERROR)
    {
        ChipLogError(DeviceLayer, "mDNS UDP listener failed: %" CHIP_ERROR_FORMAT, listenerErr.Format());
    }

    ChipLogProgress(DeviceLayer, "Zephyr platform mDNS initialized");

    if (initCallback != nullptr)
    {
        initCallback(context, CHIP_NO_ERROR);
    }

    return CHIP_NO_ERROR;
}

void ChipDnssdShutdown()
{
    if (sMdnsEndpoint4)
    {
        sMdnsEndpoint4->Close();
        sMdnsEndpoint4 = nullptr;
    }

#ifdef CONFIG_MDNS_RESPONDER
    mdns_responder_set_ext_records(nullptr, 0);
#endif
    memset(sServices, 0, sizeof(sServices));
    sActiveCount   = 0;
    sInitialized   = false;
    sErrorCallback = nullptr;
    sErrorContext  = nullptr;

    ChipLogProgress(DeviceLayer, "Zephyr platform mDNS shut down");
}

CHIP_ERROR ChipDnssdRemoveServices()
{
    for (size_t i = 0; i < kMaxServices; i++)
    {
        sServices[i].active = false;
    }

    /* Don't call UpdateExtRecords here — wait for FinalizeServiceUpdate */
    return CHIP_NO_ERROR;
}

CHIP_ERROR ChipDnssdPublishService(const DnssdService * service, DnssdPublishCallback callback, void * context)
{
    VerifyOrReturnError(service != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(sInitialized, CHIP_ERROR_INCORRECT_STATE);

    /* Map CHIP protocol enum to DNS-SD protocol string */
    const char * proto;
    switch (service->mProtocol)
    {
    case DnssdServiceProtocol::kDnssdProtocolUdp:
        proto = "_udp";
        break;
    case DnssdServiceProtocol::kDnssdProtocolTcp:
        proto = "_tcp";
        break;
    default:
        return CHIP_ERROR_INVALID_ARGUMENT;
    }

    /* Build the service type with underscore prefix if needed */
    char serviceType[kMaxServiceLen + 1];
    if (service->mType[0] == '_')
    {
        strncpy(serviceType, service->mType, sizeof(serviceType) - 1);
    }
    else
    {
        serviceType[0] = '_';
        strncpy(&serviceType[1], service->mType, sizeof(serviceType) - 2);
    }
    serviceType[sizeof(serviceType) - 1] = '\0';

    ServiceRecord * rec = FindOrAllocate(serviceType, proto, service->mName);
    VerifyOrReturnError(rec != nullptr, CHIP_ERROR_NO_MEMORY);

    /* Fill the record */
    strncpy(rec->instance, service->mName, sizeof(rec->instance) - 1);
    rec->instance[sizeof(rec->instance) - 1] = '\0';

    strncpy(rec->service, serviceType, sizeof(rec->service) - 1);
    rec->service[sizeof(rec->service) - 1] = '\0';

    strncpy(rec->proto, proto, sizeof(rec->proto) - 1);
    rec->proto[sizeof(rec->proto) - 1] = '\0';

    /* Port in network byte order */
    rec->portBe = sys_cpu_to_be16(service->mPort);

    /* Encode TXT records */
    if (service->mTextEntries != nullptr && service->mTextEntrySize > 0)
    {
        rec->txtSize = EncodeTxtRecords(service->mTextEntries, service->mTextEntrySize, rec->txt, sizeof(rec->txt));
    }
    else
    {
        rec->txtSize = 0;
    }

    rec->active = true;

    ChipLogProgress(DeviceLayer, "mDNS: publish %s.%s.%s port %u (%u TXT bytes)", rec->instance, rec->service, rec->proto,
                    service->mPort, static_cast<unsigned>(rec->txtSize));

    if (callback != nullptr)
    {
        callback(context, serviceType, service->mName, CHIP_NO_ERROR);
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR ChipDnssdFinalizeServiceUpdate()
{
    UpdateExtRecords();
    return CHIP_NO_ERROR;
}

CHIP_ERROR ChipDnssdBrowse(const char * type, DnssdServiceProtocol protocol, chip::Inet::IPAddressType addressType,
                            chip::Inet::InterfaceId interface, DnssdBrowseCallback callback, void * context,
                            intptr_t * browseIdentifier)
{
    /* Browse is a commissioner operation — not needed on a Matter device. */
    return CHIP_ERROR_NOT_IMPLEMENTED;
}

CHIP_ERROR ChipDnssdStopBrowse(intptr_t browseIdentifier)
{
    return CHIP_ERROR_NOT_IMPLEMENTED;
}

CHIP_ERROR ChipDnssdResolve(DnssdService * browseResult, chip::Inet::InterfaceId interface, DnssdResolveCallback callback,
                             void * context)
{
    /* Resolve is a commissioner operation — not needed on a Matter device. */
    return CHIP_ERROR_NOT_IMPLEMENTED;
}

void ChipDnssdResolveNoLongerNeeded(const char * instanceName) {}

CHIP_ERROR ChipDnssdReconfirmRecord(const char * hostname, chip::Inet::IPAddress address, chip::Inet::InterfaceId interface)
{
    return CHIP_NO_ERROR;
}

} /* namespace Dnssd */
} /* namespace chip */
