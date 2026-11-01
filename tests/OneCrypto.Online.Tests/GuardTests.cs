using System.Net;
using RecursiveAI.OneCrypto.Online;

namespace OneCrypto.Online.Tests;

public class GuardTests
{
    [Theory]
    // IPv4
    [InlineData("0.0.0.0")]
    [InlineData("0.1.2.3")]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.255")]
    [InlineData("100.64.0.1")]
    [InlineData("100.127.255.254")]
    [InlineData("127.0.0.1")]
    [InlineData("127.255.0.9")]
    [InlineData("169.254.169.254")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.0.0.8")]
    [InlineData("192.0.2.1")]
    [InlineData("192.168.1.1")]
    [InlineData("198.18.0.1")]
    [InlineData("198.19.255.255")]
    [InlineData("198.51.100.7")]
    [InlineData("203.0.113.9")]
    [InlineData("224.0.0.1")]
    [InlineData("239.255.255.250")]
    [InlineData("240.0.0.1")]
    [InlineData("255.255.255.255")]
    // IPv6
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("febf::1")]
    [InlineData("fc00::1")]
    [InlineData("fd12:3456:789a::1")]
    [InlineData("ff02::1")]
    [InlineData("fec0::1")]
    [InlineData("2001:db8::1")]
    [InlineData("2001::1")]
    [InlineData("100::1")]
    // IPv4 forms inside IPv6: mapped, NAT64, 6to4, IPv4-compatible
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:7f00:1")]
    [InlineData("::ffff:10.1.2.3")]
    [InlineData("::ffff:192.168.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("64:ff9b::7f00:1")]
    [InlineData("64:ff9b::10.0.0.1")]
    [InlineData("64:ff9b::a9fe:a9fe")]
    [InlineData("64:ff9b:1::1")]
    [InlineData("2002:7f00:1::1")]
    [InlineData("2002:0a00:0001::")]
    [InlineData("::127.0.0.1")]
    [InlineData("::10.0.0.1")]
    public void BlockedAddressesAreRefusedWithAReason(string text)
    {
        string? why = NetworkGuard.Default.Check(IPAddress.Parse(text));
        Assert.NotNull(why);
        Assert.NotEmpty(why);
    }

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("93.184.216.34")]
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.1")]
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.1")]
    [InlineData("192.0.1.1")]
    [InlineData("198.17.255.255")]
    [InlineData("198.20.0.1")]
    [InlineData("223.255.255.255")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("2a00:1450:4001:81b::200e")]
    [InlineData("::ffff:8.8.8.8")]
    [InlineData("64:ff9b::808:808")]
    [InlineData("2002:0808:0808::1")]
    [InlineData("2001:4860:4860::8888")]
    public void PublicAddressesPass(string text) => Assert.Null(NetworkGuard.Default.Check(IPAddress.Parse(text)));

    [Theory]
    [InlineData("http://127.0.0.1/")]
    [InlineData("http://127.1/")]
    [InlineData("http://0x7f.0.0.1/")]
    [InlineData("http://2130706433/")]
    [InlineData("http://017700000001/")]
    [InlineData("http://[::1]/")]
    [InlineData("http://[::ffff:127.0.0.1]/")]
    [InlineData("http://[::ffff:7f00:1]:8080/crl")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("http://10.0.0.5:8080/ocsp")]
    [InlineData("http://localhost/")]
    [InlineData("http://LOCALHOST./")]
    [InlineData("http://ca.localhost/")]
    [InlineData("https://0.0.0.0/")]
    public void LiteralHostsAreCaughtInEveryNotation(string url) => Assert.NotNull(NetworkGuard.Default.CheckLiteral(new Uri(url)));

    [Theory]
    [InlineData("http://example.com/")]
    [InlineData("http://8.8.8.8/")]
    [InlineData("https://[2606:4700:4700::1111]/")]
    [InlineData("http://localhost.example.com/")]
    public void OrdinaryHostsAreNotCaughtByTheLiteralCheck(string url) => Assert.Null(NetworkGuard.Default.CheckLiteral(new Uri(url)));

    [Fact]
    public void AnAllowedNetworkOpensExactlyThatRange()
    {
        var guard = new NetworkGuard { AllowedNetworks = [IPNetwork.Parse("10.1.0.0/16")] };
        Assert.Null(guard.Check(IPAddress.Parse("10.1.2.3")));
        Assert.Null(guard.Check(IPAddress.Parse("::ffff:10.1.2.3")));
        Assert.NotNull(guard.Check(IPAddress.Parse("10.2.0.1")));
        Assert.NotNull(guard.Check(IPAddress.Parse("127.0.0.1")));
    }

    [Fact]
    public void AllowAllLetsEverythingThrough()
    {
        Assert.Null(NetworkGuard.AllowAll.Check(IPAddress.Loopback));
        Assert.Null(NetworkGuard.AllowAll.CheckLiteral(new Uri("http://localhost/")));
    }
}
