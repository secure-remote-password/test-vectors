## SRP-6a test vectors

This repository contains test vectors for validating the SRP-6a protocol implementations.  
Test vectors are JSON files specifying the exact values for each authentication step.  
Each file contains a set of test vectors for different initialization parameters.

## Usage

* Load test vectors using a suitable JSON implementation for your platform. 
* Initialize your SRP library using `H`, `N`, `g` and `size` parameters.
* Ignore the test vector if your library doesn't support the specified hash function.
* Verify each computation step against the values from the test vector.

## Test vector parameters

* `H` — hash function: sha1, sha256, sha512, blake2b-256, etc.
* `size` — prime number size (bits)
* `N` — large safe prime number
* `g` — group generator
* `I` — user identifier (user name, email, etc)
* `P` — user password
* `s` — salt
* `k` — multiplier parameter
* `x` — private key, derived from the user name, password and salt
* `v` — verifier, derived from the private key
* `a` — client secret ephemeral value
* `b` — server secret ephemeral value
* `A` — client public ephemeral value
* `B` — server public ephemeral value 
* `u` — u, derived from A and B
* `S` — premaster secret, computed by client and server
* `K` — shared session key (optional)
* `M1` — client session proof (optional)
* `M2` — server session proof (optional)

Note: `K`, `M1` and `M2` parameters may be missing in the test vector.  
RFC5054 document doesn't specify these values. They are calculated as follows:

* K = [H(S)](https://github.com/secure-remote-password/stanford-srp/blob/587900d32777348f98477cb25123d5761fbe3725/libsrp/srp6_client.c#L272)
* M1 = [H(H(N) xor H(g), H(I), s, A, B, K)](https://github.com/secure-remote-password/stanford-srp/blob/master/libsrp/srp6_client.c#L275)
* M2 = [H(A, M1, K)](https://github.com/secure-remote-password/stanford-srp/blob/master/libsrp/srp6_server.c#L372)

# Code examples

Test vector definition in C#:

```c#
public class TestVectorSet
{
	public string Comments { get; set; }
	public string Url { get; set; }
	public TestVector[] TestVectors { get; set; }
}

public class TestVector
{
	public string H { get; set; }
	public int Size { get; set; }
	public string N { get; set; }
	public string g { get; set; }
	public string I { get; set; }
	public string P { get; set; }
	public string s { get; set; }
	public string k { get; set; }
	public string x { get; set; }
	public string v { get; set; }
	public string a { get; set; }
	public string b { get; set; }
	public string A { get; set; }
	public string B { get; set; }
	public string u { get; set; }
	public string S { get; set; }

	// optional parameters, missing in RFC5054 test vector
	public string K { get; set; }
	public string M1 { get; set; }
	public string M2 { get; set; }
}
```

Loading test vectors from a file:

```c#
using Newtonsoft.Json;

var json = File.ReadAllText("rfc5054.json");
var testVectors = JsonConvert.DeserializeObject<TestVectorSet>(json);

foreach (var tv in testVectors.TestVectors)
{
	VerifyTestVector(tv);
}
```

Verifying a SRP implementation using a test vector:

```c#
private void VerifyTestVector(TestVector testVector)
{
	// prepare SRP parameters
	var parameters = CreateParameters(testVector);
	var N = parameters.N;
	var g = parameters.G;
	var H = parameters.H;

	// validate the multiplier parameter
	var k = parameters.K;
	var kx = SrpInteger.FromHex(testVector.k);
	Assert.AreEqual(kx, k);

	// prepare user name, password and salt
	var I = testVector.I;
	var P = testVector.P;
	var s = SrpInteger.FromHex(testVector.s).ToHex();
	var client = new SrpClient(parameters);
	var server = new SrpServer(parameters);

	// validate the private key
	var x = SrpInteger.FromHex(client.DerivePrivateKey(s, I, P));
	var xx = SrpInteger.FromHex(testVector.x);
	Assert.AreEqual(xx, x);

	// validate the verifier
	var v = SrpInteger.FromHex(client.DeriveVerifier(x));
	var vx = SrpInteger.FromHex(testVector.v);
	Assert.AreEqual(vx, v);

	// client ephemeral
	var a = SrpInteger.FromHex(testVector.a);
	var A = client.ComputeA(a);
	var Ax = SrpInteger.FromHex(testVector.A);
	Assert.AreEqual(Ax, A);
	var clientEphemeral = new SrpEphemeral { Public = A, Secret = a };

	// server ephemeral
	var b = SrpInteger.FromHex(testVector.b);
	var B = server.ComputeB(v, b);
	var Bx = SrpInteger.FromHex(testVector.B);
	Assert.AreEqual(Bx, B);
	var serverEphemeral = new SrpEphemeral { Public = B, Secret = a };

	// validate u
	var u = client.ComputeU(A, B);
	var ux = SrpInteger.FromHex(testVector.u);
	Assert.AreEqual(ux, u);

	// premaster secret — client version
	var S = client.ComputeS(a, B, u, x);
	var Sx = SrpInteger.FromHex(testVector.S);
	Assert.AreEqual(Sx, S);

	// premaster secret — server version
	S = server.ComputeS(A, b, u, v);
	Assert.AreEqual(Sx, S);

	// client session
	var clientSession = client.DeriveSession(a, B, s, I, x);
	if (testVector.M1 != null)
	{
		Assert.AreEqual(testVector.M1, clientSession.Proof);
	}

	// server session
	var serverSession = server.DeriveSession(b, A, s, I, v, clientSession.Proof);
	Assert.AreEqual(clientSession.Key, serverSession.Key);
	if (testVector.M2 != null)
	{
		Assert.AreEqual(testVector.M2, serverSession.Proof);
	}

	// verify server session
	client.VerifySession(A, clientSession, serverSession.Proof);
	if (testVector.K != null)
	{
		Assert.AreEqual(testVector.K, serverSession.Key);
	}
}
```
