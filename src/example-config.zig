pub const nft: []const u8 =
    \\table inet filter {
    \\    set abuse {
    \\        type ipv4_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\    }
    \\    set abuse-http {
    \\        type ipv4_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\    }
    \\    set abuse-mail {
    \\        type ipv4_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\    }
    \\    set abuse-sshd {
    \\        type ipv4_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\    }
    \\
    \\    set abuse-v6 {
    \\        type ipv6_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\    }
    \\    set abuse-http-v6 {
    \\        type ipv6_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\    }
    \\    set abuse-mail-v6 {
    \\        type ipv6_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\    }
    \\    set abuse-sshd-v6 {
    \\        type ipv6_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\    }
    \\
    \\
    \\    chain input {
    \\        type filter hook input priority 0; policy accept;
    \\
    \\        ip saddr @abuse counter drop
    \\        ip saddr @abuse-http tcp dport { 80, 443 } counter reject with icmpx 3
    \\        ip saddr @abuse-mail tcp dport { 25, 143, 465, 587, 993, } counter reject with icmpx 3
    \\        ip saddr @abuse-sshd tcp dport 22 counter drop
    \\
    \\        ip6 saddr @abuse-v6 counter drop
    \\        ip6 saddr @abuse-http-v6 tcp dport { 80, 443 } counter reject with icmpx 3
    \\        ip6 saddr @abuse-mail-v6 tcp dport { 25, 143, 465, 587, 993, } counter reject with icmpx 3
    \\        ip6 saddr @abuse-sshd-v6 tcp dport 22 counter drop
    \\
    \\        iifname "lo" accept comment "Accept any localhost traffic"
    \\        ct state { 0x2, 0x4 } accept comment "Accept traffic originated from us"
    \\        ip protocol 1 icmp type { 0, 3, 8, 11, 12 } accept comment "Accept ICMP"
    \\    }
    \\
    \\    chain forward {
    \\        type filter hook forward priority 0; policy accept;
    \\    }
    \\
    \\    chain output {
    \\        type filter hook output priority 0; policy accept;
    \\    }
    \\}
    \\
;
