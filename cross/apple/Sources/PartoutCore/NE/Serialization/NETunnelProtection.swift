// SPDX-FileCopyrightText: 2026 Davide De Rosa
//
// SPDX-License-Identifier: GPL-3.0

import NetworkExtension

/// Device policy supplied by the application, never inferred from an imported profile.
public enum NETunnelProtection: String, Sendable {
    case disabled
    case requireVPN

    public static let configurationKey = "Partout.RequireVPN"

    /// The saved marker lets unattended provider starts enforce the same policy.
    /// A malformed marker must not silently weaken the configuration.
    public init(protocolConfiguration: NEVPNProtocol) throws {
        guard let configuration = protocolConfiguration as? NETunnelProviderProtocol else {
            throw NETunnelProtectionError.invalidConfiguration
        }
        guard let marker = configuration.providerConfiguration?[Self.configurationKey] else {
            self = .disabled
            return
        }
        guard let value = marker as? String, let policy = Self(rawValue: value) else {
            throw NETunnelProtectionError.invalidConfiguration
        }
        self = policy
    }

    public func apply(to configuration: NETunnelProviderProtocol, profile: Profile) throws {
        try validate(profile)
        guard self == .requireVPN else {
            configuration.disconnectOnSleep = profile.disconnectsOnSleep
#if !os(tvOS)
            configuration.includeAllNetworks = profile.includesAllNetworks
#endif
            configuration.providerConfiguration?.removeValue(forKey: Self.configurationKey)
            return
        }
#if os(tvOS)
        throw NETunnelProtectionError.unsupportedPlatform
#else
        guard #available(macOS 26, iOS 26, *) else {
            throw NETunnelProtectionError.unsupportedPlatform
        }
        configuration.includeAllNetworks = true
        configuration.disconnectOnSleep = false
        configuration.excludeLocalNetworks = false
        configuration.excludeAPNs = false
        configuration.excludeCellularServices = false
        configuration.excludeDeviceCommunication = false
        var metadata = configuration.providerConfiguration ?? [:]
        metadata[Self.configurationKey] = rawValue
        configuration.providerConfiguration = metadata
#endif
    }

    /// Initial strict support is limited to unattended OpenVPN or WireGuard with
    /// provisioned numeric endpoints. It never grants physical-network DNS access.
    public func validate(_ profile: Profile) throws {
        guard self == .requireVPN else { return }
#if os(tvOS)
        throw NETunnelProtectionError.unsupportedPlatform
#else
        guard #available(macOS 26, iOS 26, *) else {
            throw NETunnelProtectionError.unsupportedPlatform
        }
        guard !profile.isInteractive else {
            throw NETunnelProtectionError.interactiveAuthentication
        }
        let connections = profile.activeModules.filter(\.buildsConnection)
        guard connections.count == 1, let connection = connections.first else {
            throw NETunnelProtectionError.unsupportedConnection
        }
        let addresses: [Address]
        if let module = connection as? OpenVPNModule,
           let configuration = module.configuration {
            guard configuration.randomizeHostnames != true else {
                throw NETunnelProtectionError.numericEndpointRequired
            }
            addresses = configuration.remotes?.map(\.address) ?? []
        } else if let module = connection as? WireGuardModule,
                  let configuration = module.configuration {
            guard !configuration.peers.isEmpty,
                  configuration.peers.allSatisfy({ $0.endpoint != nil }) else {
                throw NETunnelProtectionError.numericEndpointRequired
            }
            addresses = configuration.peers.compactMap(\.endpoint?.address)
        } else {
            throw NETunnelProtectionError.unsupportedConnection
        }
        guard !addresses.isEmpty, addresses.allSatisfy({ Address(rawValue: $0.rawValue)?.isIPAddress == true }) else {
            throw NETunnelProtectionError.numericEndpointRequired
        }
        guard !profile.activeModules.contains(where: { ($0 as? DNSModule)?.routesThroughVPN == false }) else {
            throw NETunnelProtectionError.dnsOutsideTunnel
        }
#endif
    }

    public func validate(_ settings: NEPacketTunnelNetworkSettings) throws {
        guard self == .requireVPN else { return }
        guard let ipv4 = settings.ipv4Settings,
              ipv4.includedRoutes?.contains(where: { $0.hasSameDestination(as: .default()) }) == true,
              let ipv6 = settings.ipv6Settings,
              ipv6.includedRoutes?.contains(where: { $0.hasSameDestination(as: .default()) }) == true else {
            throw NETunnelProtectionError.incompleteIPCoverage
        }
        guard (ipv4.excludedRoutes ?? []).isEmpty, (ipv6.excludedRoutes ?? []).isEmpty else {
            throw NETunnelProtectionError.excludedRoutes
        }
        guard settings.proxySettings == nil else {
            throw NETunnelProtectionError.unsupportedConnection
        }
        guard let dns = settings.dnsSettings, !dns.servers.isEmpty,
              dns.servers.allSatisfy({ Address(rawValue: $0)?.isIPAddress == true }),
              dns.matchDomains == [""] else {
            throw NETunnelProtectionError.approvedDNSRequired
        }
        guard #available(macOS 26, iOS 26, tvOS 26, *) else {
            throw NETunnelProtectionError.unsupportedPlatform
        }
        dns.allowFailover = false
    }
}

public enum NETunnelProtectionError: Error, Equatable, Sendable {
    case invalidConfiguration
    case unsupportedPlatform
    case interactiveAuthentication
    case unsupportedConnection
    case numericEndpointRequired
    case dnsOutsideTunnel
    case approvedDNSRequired
    case incompleteIPCoverage
    case excludedRoutes
}
