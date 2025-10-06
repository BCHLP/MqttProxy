using System.Security.Cryptography.X509Certificates;
using System.Text;

class CertificateValidator
{
    public void Main()
    {
        Console.WriteLine("=== Certificate Chain Validator ===");
        Console.WriteLine("This tool helps debug certificate issues in your MQTT setup");
        Console.WriteLine();

        string certsPath = "../../../certs/"; // Adjust path as needed

        try
        {
            // Test 1: Load and examine CA chain
            Console.WriteLine("🔍 Testing CA Chain Loading...");
            var caCerts = LoadCertificateChain(certsPath + "ca-chain.crt");

            if (caCerts.Count == 0)
            {
                Console.WriteLine("❌ No CA certificates loaded! Check the ca-chain.crt file path and format.");
                return;
            }

            Console.WriteLine($"✅ Loaded {caCerts.Count} CA certificates:");
            for (int i = 0; i < caCerts.Count; i++)
            {
                var cert = caCerts[i];
                Console.WriteLine($"   {i + 1}. Subject: {cert.Subject}");
                Console.WriteLine($"      Issuer: {cert.Issuer}");
                Console.WriteLine($"      Valid: {cert.NotBefore:yyyy-MM-dd} to {cert.NotAfter:yyyy-MM-dd}");
                Console.WriteLine($"      Is CA: {cert.Extensions["2.5.29.19"] != null}"); // Basic Constraints extension
                Console.WriteLine();
            }

            // Test 2: Load and validate client certificate
            Console.WriteLine("🔍 Testing Client Certificate...");
            string clientCertPath = certsPath + "macbookpro.pfx";

            if (!File.Exists(clientCertPath))
            {
                Console.WriteLine($"❌ Client certificate not found at: {clientCertPath}");
                return;
            }

            var clientCert = new X509Certificate2(clientCertPath, "", X509KeyStorageFlags.Exportable);
            Console.WriteLine($"✅ Client certificate loaded:");
            Console.WriteLine($"   Subject: {clientCert.Subject}");
            Console.WriteLine($"   Issuer: {clientCert.Issuer}");
            Console.WriteLine($"   Valid: {clientCert.NotBefore:yyyy-MM-dd} to {clientCert.NotAfter:yyyy-MM-dd}");
            Console.WriteLine($"   Has Private Key: {clientCert.HasPrivateKey}");
            Console.WriteLine();

            // Test 3: Validate client certificate against CA chain
            Console.WriteLine("🔍 Testing Client Certificate Validation...");
            bool isValid = ValidateClientCertificate(clientCert, caCerts);

            if (isValid)
            {
                Console.WriteLine("🎉 All tests passed! Your certificates should work with mutual TLS.");
            }
            else
            {
                Console.WriteLine("❌ Certificate validation failed. Check the issues above.");
            }

            // Test 4: Load and validate server certificate
            Console.WriteLine("\n🔍 Testing Server Certificate...");
            string serverCertPath = certsPath + "mqtt-broker.pfx";

            if (File.Exists(serverCertPath))
            {
                var serverCert = new X509Certificate2(serverCertPath, "", X509KeyStorageFlags.Exportable);
                Console.WriteLine($"✅ Server certificate loaded:");
                Console.WriteLine($"   Subject: {serverCert.Subject}");
                Console.WriteLine($"   Issuer: {serverCert.Issuer}");
                Console.WriteLine($"   Valid: {serverCert.NotBefore:yyyy-MM-dd} to {serverCert.NotAfter:yyyy-MM-dd}");
                Console.WriteLine($"   Has Private Key: {serverCert.HasPrivateKey}");

                bool serverValid = ValidateClientCertificate(serverCert, caCerts);
                Console.WriteLine($"   Validates against CA chain: {(serverValid ? "✅ Yes" : "❌ No")}");
            }
            else
            {
                Console.WriteLine($"❌ Server certificate not found at: {serverCertPath}");
            }

        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
        }

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }

    bool ValidateClientCertificate(X509Certificate2 clientCert, List<X509Certificate2> caCerts)
    {
        try
        {
            // Check certificate validity period
            var now = DateTime.Now;
            if (now < clientCert.NotBefore)
            {
                Console.WriteLine($"   ❌ Certificate not yet valid (valid from {clientCert.NotBefore:yyyy-MM-dd})");
                return false;
            }

            if (now > clientCert.NotAfter)
            {
                Console.WriteLine($"   ❌ Certificate expired (expired on {clientCert.NotAfter:yyyy-MM-dd})");
                return false;
            }

            Console.WriteLine($"   ✅ Certificate is within validity period");

            // Build certificate chain
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

            // Add trusted CAs
            foreach (var caCert in caCerts)
            {
                chain.ChainPolicy.CustomTrustStore.Add(caCert);
            }

            bool isValid = chain.Build(clientCert);

            if (isValid)
            {
                Console.WriteLine($"   ✅ Certificate chain validation successful");
                Console.WriteLine($"   📋 Certificate chain:");
                for (int i = 0; i < chain.ChainElements.Count; i++)
                {
                    var element = chain.ChainElements[i];
                    string certType = i == 0 ? "End Entity" :
                                     i == chain.ChainElements.Count - 1 ? "Root CA" :
                                     "Intermediate CA";
                    Console.WriteLine($"      {i}: {certType} - {element.Certificate.Subject}");
                }
            }
            else
            {
                Console.WriteLine($"   ❌ Certificate chain validation failed:");
                foreach (var status in chain.ChainStatus)
                {
                    Console.WriteLine($"      - {status.Status}: {status.StatusInformation}");
                }

                // Show what we found in the chain
                Console.WriteLine($"   📋 Chain elements found:");
                for (int i = 0; i < chain.ChainElements.Count; i++)
                {
                    var element = chain.ChainElements[i];
                    Console.WriteLine($"      {i}: {element.Certificate.Subject}");
                    if (element.ChainElementStatus.Length > 0)
                    {
                        foreach (var status in element.ChainElementStatus)
                        {
                            Console.WriteLine($"         ⚠️  {status.Status}: {status.StatusInformation}");
                        }
                    }
                }
            }

            return isValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ Certificate validation error: {ex.Message}");
            return false;
        }
    }

    List<X509Certificate2> LoadCertificateChain(string chainFilePath)
    {
        var certs = new List<X509Certificate2>();

        try
        {
            if (!File.Exists(chainFilePath))
            {
                Console.WriteLine($"❌ Certificate chain file not found: {chainFilePath}");
                return certs;
            }

            var chainContent = File.ReadAllText(chainFilePath);
            var certStrings = SplitPemCertificates(chainContent);

            foreach (var certString in certStrings)
            {
                var cert = new X509Certificate2(Encoding.UTF8.GetBytes(certString));
                certs.Add(cert);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error loading certificate chain: {ex.Message}");
        }

        return certs;
    }

    List<string> SplitPemCertificates(string pemContent)
    {
        var certs = new List<string>();
        var lines = pemContent.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        var currentCert = new List<string>();
        bool inCert = false;

        foreach (var line in lines)
        {
            if (line.Contains("-----BEGIN CERTIFICATE-----"))
            {
                inCert = true;
                currentCert.Clear();
                currentCert.Add(line);
            }
            else if (line.Contains("-----END CERTIFICATE-----"))
            {
                currentCert.Add(line);
                certs.Add(string.Join("\n", currentCert));
                inCert = false;
            }
            else if (inCert)
            {
                currentCert.Add(line);
            }
        }

        return certs;
    }
}