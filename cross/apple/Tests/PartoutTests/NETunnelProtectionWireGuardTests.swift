// SPDX-FileCopyrightText: 2026 Davide De Rosa
//
// SPDX-License-Identifier: GPL-3.0

#if !os(tvOS)

import Foundation
import NetworkExtension
@testable import PartoutCore
import Testing

struct NETunnelProtectionWireGuardTests {
    @available(macOS 26, iOS 26, *)
    @Test(arguments: ["192.0.2.1:51820", "[2001:db8::1]:51820"])
    func numericEndpointAcceptsGeneratedDualStackSettings(_ endpoint: String) throws {
        let fixture = try fixture(endpoint: endpoint)
        let settings = try fixture.profile.protectedNetworkSettings(with: fixture.info)
        let ipv4 = try #require(settings.ipv4Settings)
        let ipv6 = try #require(settings.ipv6Settings)
        #expect(ipv4.addresses == ["10.8.0.2"])
        #expect(ipv6.addresses == ["fd00::2"])
        #expect(ipv4.includedRoutes?.contains { $0.hasSameDestination(as: .default()) } == true)
        #expect(ipv6.includedRoutes?.contains { $0.hasSameDestination(as: .default()) } == true)
        let dns = try #require(settings.dnsSettings)
        #expect(dns.servers == ["10.8.0.1"])
        #expect(dns.matchDomains == [""])
        #expect(dns.allowFailover == false)
    }

    @available(macOS 26, iOS 26, *)
    @Test(arguments: ["vpn.example.test:51820", nil] as [String?])
    func hostnameOrMissingEndpointIsRejected(_ endpoint: String?) throws {
        let fixture = try fixture(endpoint: endpoint)
        #expect(throws: NETunnelProtectionError.numericEndpointRequired) {
            try fixture.profile.protectedNetworkSettings(with: fixture.info)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test(arguments: [Address.Family.v4, .v6])
    func missingAddressFamilyIsRejected(_ family: Address.Family) throws {
        let fixture = try fixture(omittingFamily: family)
        #expect(throws: NETunnelProtectionError.incompleteIPCoverage) {
            try fixture.profile.protectedNetworkSettings(with: fixture.info)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test(arguments: [Address.Family.v4, .v6])
    func excludedRouteIsRejectedAfterGeneratedSettingsMerge(_ family: Address.Family) throws {
        let fixture = try fixture(excludingFamily: family)
        #expect(throws: NETunnelProtectionError.excludedRoutes) {
            try fixture.profile.protectedNetworkSettings(with: fixture.info)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test
    func generatedSettingsRequireProvisionedDNS() throws {
        var fixture = try fixture()
        fixture.info.modules = fixture.info.modules?.filter {
            guard case .DNS = $0 else { return true }
            return false
        }
        #expect(throws: NETunnelProtectionError.approvedDNSRequired) {
            try fixture.profile.protectedNetworkSettings(
                with: fixture.info,
                options: .init(dnsFallbackServers: ["1.1.1.1"], logsSnapshots: false)
            )
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test(arguments: [DNSProtocol.https, .tls])
    func encryptedDNSRemainsUnsupportedInInitialStrictSubset(_ dnsProtocol: DNSProtocol) throws {
        let fixture = try fixture(dnsProtocol: dnsProtocol)
        // Encrypted DNS currently leaves matchDomains nil. Keep its rejection
        // explicit until platform routing behavior has been verified.
        let ordinarySettings = fixture.profile.networkSettings(with: fixture.info)
        #expect(ordinarySettings.dnsSettings?.matchDomains == nil)
        #expect(ordinarySettings.dnsSettings?.servers == ["10.8.0.1"])
        #expect(throws: NETunnelProtectionError.approvedDNSRequired) {
            try fixture.profile.protectedNetworkSettings(with: fixture.info)
        }
    }

    private func fixture(
        endpoint: String? = "192.0.2.1:51820",
        omittingFamily: Address.Family? = nil,
        excludingFamily: Address.Family? = nil,
        dnsProtocol: DNSProtocol = .cleartext
    ) throws -> (profile: Profile, info: TunnelRemoteInfoWrapper) {
        // Deterministic fixture keys never leave this process or access Keychain.
        var interface = WireGuard.LocalInterface.Builder(
            privateKey: Data(repeating: 1, count: 32).base64EncodedString()
        )
        let ipv4 = omittingFamily == .v4 ? nil : IPSettings(subnet: try Subnet("10.8.0.2", 24))
            .including(routes: [Route(defaultWithGateway: nil)])
        let ipv6 = omittingFamily == .v6 ? nil : IPSettings(subnet: try Subnet("fd00::2", 64))
            .including(routes: [Route(defaultWithGateway: nil)])
        interface.addresses = (ipv4?.subnets ?? []).map(\.rawValue) + (ipv6?.subnets ?? []).map(\.rawValue)
        interface.dns = DNSModule.Builder(
            protocolType: dnsProtocol,
            servers: ["10.8.0.1"],
            dohURL: "https://dns.example.test/dns-query",
            dotHostname: "dns.example.test",
            routesThroughVPN: true
        )
        var peer = WireGuard.RemoteInterface.Builder(
            publicKey: Data(repeating: 2, count: 32).base64EncodedString()
        )
        peer.endpoint = endpoint
        peer.allowedIPs = [omittingFamily == .v4 ? nil : "0.0.0.0/0", omittingFamily == .v6 ? nil : "::/0"]
            .compactMap { $0 }
        let configuration = try WireGuard.Configuration.Builder(interface: interface, peers: [peer]).build()
        let wireGuard = WireGuardModule(id: UniqueID(), configuration: configuration)
        let profile = try Profile.Builder(modules: [wireGuard], activatingModules: true).build()

        // The native WireGuard tunnel-info builder synthesizes IP/DNS modules
        // and inserts them after the originating WireGuard module at this seam.
        var generatedIP = IPModule.Builder(ipv4: ipv4, ipv6: ipv6)
        if excludingFamily == .v4 {
            generatedIP.ipv4 = generatedIP.ipv4?.excluding(routes: [Route(try Subnet("192.168.0.0", 16), nil)])
        } else if excludingFamily == .v6 {
            generatedIP.ipv6 = generatedIP.ipv6?.excluding(routes: [Route(try Subnet("fd01::", 64), nil)])
        }
        let dns = try #require(configuration.interface.dns)
        let info = TunnelRemoteInfoWrapper(
            profile: profile.asTaggedProfile,
            originalModuleId: wireGuard.id,
            address: Address(rawValue: "127.0.0.1"),
            modules: [.IP(generatedIP.build()), .DNS(dns)]
        )
        return (profile, info)
    }
}

#endif
