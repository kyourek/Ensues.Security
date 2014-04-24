using System;
using System.IO;

using NUnit.Framework;

using Ensues.Security.Cryptography;
namespace Ensues.Configuration.Tests {
    
    [TestFixture]
    public class SecuritySectionTests {

        private string AppConfigFile;

        [SetUp]
        public void SetUp() {
            AppConfigFile = Path.GetTempFileName();
            SecurityConfiguration.Default = null;
        }

        [TearDown]
        public void TearDown() {
            File.Delete(AppConfigFile);
            SecurityConfiguration.Default = null;
        }

        [Test]
        public void PasswordAlgorithmConfiguration_ValuesSetFromAppConfig() {

            var appConfig = @"<?xml version='1.0'?>
                <configuration>
                    <configSections>
                        <section name='ensues.security' type='Ensues.Configuration.SecuritySection, Ensues.Security' />
                    </configSections>
                    <ensues.security>
                        <passwordAlgorithm hashFunction='SHA384' hashIterations='123456' compareInConstantTime='false' saltLength='321' />
                    </ensues.security>
                </configuration>
            ";

            File.WriteAllText(AppConfigFile, appConfig);

            using (AppConfig.Change(AppConfigFile)) {

                var securityConfiguration = new SecurityConfiguration();
                var passwordAlgorithmConfiguration = securityConfiguration.PasswordAlgorithmConfiguration;
                Assert.AreEqual(HashFunction.SHA384, passwordAlgorithmConfiguration.HashFunction);
                Assert.AreEqual(123456, passwordAlgorithmConfiguration.HashIterations);
                Assert.AreEqual(false, passwordAlgorithmConfiguration.CompareInConstantTime);
                Assert.AreEqual(321, passwordAlgorithmConfiguration.SaltLength);
            }
        }

        [Test]
        public void PasswordAlgorithmConfiguration_UsesDefaultsIfNotProvided() {

            var appConfig = @"<?xml version='1.0'?>
                <configuration>
                    <configSections>
                        <section name='ensues.security' type='Ensues.Configuration.SecuritySection, Ensues.Security' />
                    </configSections>
                    <ensues.security>
                        <passwordAlgorithm />
                    </ensues.security>
                </configuration>
            ";

            File.WriteAllText(AppConfigFile, appConfig);

            using (AppConfig.Change(AppConfigFile)) {

                var securityConfiguration = new SecurityConfiguration();
                var passwordAlgorithmConfiguration = securityConfiguration.PasswordAlgorithmConfiguration;
                Assert.AreEqual(PasswordAlgorithm.HashFunctionDefault, passwordAlgorithmConfiguration.HashFunction);
                Assert.AreEqual(PasswordAlgorithm.HashIterationsDefault, passwordAlgorithmConfiguration.HashIterations);
                Assert.AreEqual(PasswordAlgorithm.CompareInConstantTimeDefault, passwordAlgorithmConfiguration.CompareInConstantTime);
                Assert.AreEqual(PasswordAlgorithm.SaltLengthDefault, passwordAlgorithmConfiguration.SaltLength);
            }
        }
    }
}
