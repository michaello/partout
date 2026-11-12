// SPDX-FileCopyrightText: 2026 Davide De Rosa
//
// SPDX-License-Identifier: GPL-3.0

#if !os(tvOS)

import NetworkExtension
@testable import PartoutCore
import Testing

struct NETunnelProtectionTests {
    @available(macOS 26, iOS 26, *)
    @Test(arguments: ["require-vpn", "", "true"])
    func malformedSavedPolicyIsRejected(_ marker: String) {
        let configuration = NETunnelProviderProtocol()
        configuration.providerConfiguration = [NETunnelProtection.configurationKey: marker]
        #expect(throws: NETunnelProtectionError.invalidConfiguration) {
            try NETunnelProtection(protocolConfiguration: configuration)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test
    func fullTunnelDNSDisablesSystemResolverFailover() throws {
        let settings = try profile().protectedNetworkSettings(with: nil)
        #expect(settings.dnsSettings?.servers == ["10.8.0.1"])
        if #available(macOS 26, iOS 26, tvOS 26, *) {
            #expect(settings.dnsSettings?.allowFailover == false)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test(arguments: ["vpn.example.com", ""])
    func unprovisionedEndpointIsRejected(_ address: String) throws {
        #expect(throws: NETunnelProtectionError.numericEndpointRequired) {
            try NETunnelProtection.requireVPN.validate(profile(endpoint: address))
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test
    func unsupportedFamilyIsRejected() throws {
        #expect(throws: NETunnelProtectionError.incompleteIPCoverage) {
            try profile(includeIPv6: false).protectedNetworkSettings(with: nil)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test
    func configuredFallbackDoesNotSubstituteForApprovedDNS() throws {
        #expect(throws: NETunnelProtectionError.approvedDNSRequired) {
            try profile(includeDNS: false).protectedNetworkSettings(
                with: nil,
                options: .init(dnsFallbackServers: ["1.1.1.1"], logsSnapshots: false)
            )
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test
    func explicitDNSBypassIsRejected() throws {
        #expect(throws: NETunnelProtectionError.dnsOutsideTunnel) {
            try profile(dnsThroughVPN: false).protectedNetworkSettings(with: nil)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test
    func serverPushedDNSBypassIsRejectedAfterMerging() throws {
        let profile = try profile()
        let module = try #require(profile.firstBuildingConnection(ifActive: true))
        let remoteDNS = try DNSModule.Builder(servers: ["8.8.8.8"], routesThroughVPN: false).build()
        let info = TunnelRemoteInfoWrapper(
            profile: profile.asTaggedProfile,
            originalModuleId: module.id,
            address: Address(rawValue: "192.0.2.1"),
            modules: [.DNS(remoteDNS)]
        )
        #expect(throws: NETunnelProtectionError.dnsOutsideTunnel) {
            try profile.protectedNetworkSettings(with: info)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test
    func routeExclusionIsRejectedAfterMerging() throws {
        let settings = try profile().protectedNetworkSettings(with: nil)
        settings.ipv4Settings?.excludedRoutes = [NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0")]
        #expect(throws: NETunnelProtectionError.excludedRoutes) {
            try NETunnelProtection.requireVPN.validate(settings)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test
    func splitDNSIsRejected() throws {
        let settings = try profile().protectedNetworkSettings(with: nil)
        settings.dnsSettings?.matchDomains = ["example.com"]
        #expect(throws: NETunnelProtectionError.approvedDNSRequired) {
            try NETunnelProtection.requireVPN.validate(settings)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test
    func interactiveAuthenticationIsRejectedBeforeSaving() throws {
        let module = OpenVPNModule(
            id: UniqueID(),
            configuration: .init(remotes: [try ExtendedEndpoint("192.0.2.1", .init(.udp, 1194))]),
            requiresInteractiveCredentials: true
        )
        let profile = try Profile.Builder(modules: [module], activatingModules: true).build()
        #expect(throws: NETunnelProtectionError.interactiveAuthentication) {
            try NETunnelProtection.requireVPN.validate(profile)
        }
    }

    @available(macOS 26, iOS 26, *)
    @Test
    func nonStringSavedPolicyIsRejected() {
        let configuration = NETunnelProviderProtocol()
        configuration.providerConfiguration = [NETunnelProtection.configurationKey: true]
        #expect(throws: NETunnelProtectionError.invalidConfiguration) {
            try NETunnelProtection(protocolConfiguration: configuration)
        }
    }

    private func profile(
        endpoint: String = "192.0.2.1",
        includeIPv6: Bool = true,
        includeDNS: Bool = true,
        dnsThroughVPN: Bool = true
    ) throws -> Profile {
        let connection = OpenVPNModule(
            id: UniqueID(),
            configuration: .init(remotes: Address(rawValue: endpoint).map { [.init($0, .init(.udp, 1194))] } ?? [])
        )
        let ip = IPModule.Builder(
            ipv4: IPSettings(subnet: try Subnet("10.8.0.2", 24))
                .including(routes: [Route(defaultWithGateway: nil)]),
            ipv6: includeIPv6 ? IPSettings(subnet: try Subnet("fd00::2", 64))
                .including(routes: [Route(defaultWithGateway: nil)]) : nil
        ).build()
        var modules: [any Module] = [connection, ip]
        if includeDNS {
            modules.append(try DNSModule.Builder(servers: ["10.8.0.1"], routesThroughVPN: dnsThroughVPN).build())
        }
        return try Profile.Builder(modules: modules, activatingModules: true).build()
    }
}

#endif
