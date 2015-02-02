using System;

using NUnit.Framework;

using Ensues.Security.Cryptography;
namespace Ensues.Configuration {
    [TestFixture]
    public class SecurityConfigurationTests {
        [SetUp]
        public void SetUp() {
            SecurityConfiguration.Default.Reset();
        }

        [Test]
        public void ConfigurePasswordAlgorithm_ConfiguresInstance() {
            var appConfig = @"<?xml version='1.0'?>
                <configuration>
                    <configSections>
                        <section name='ensues.security' type='Ensues.Configuration.SecuritySection, Ensues.Security' />
                    </configSections>
                    <ensues.security>
                        <passwordAlgorithm hashFunction='SHA384' hashIterations='123456' compareInConstantTime='false' saltLength='321' />
                        <passwordGenerator length='100' symbols='abcdefghijklmnopqrstuvwxyz' />
                    </ensues.security>
                </configuration>
            ";
            using (AppConfig.With(appConfig)) {
                var algo = new PasswordAlgorithm();
                SecurityConfiguration.Default.ConfigurePasswordAlgorithm(algo);
                Assert.AreEqual(HashFunction.SHA384, algo.HashFunction);
                Assert.AreEqual(123456, algo.HashIterations);
                Assert.AreEqual(false, algo.CompareInConstantTime);
                Assert.AreEqual(321, algo.SaltLength);
            }
        }

        [Test]
        public void ConfigurePasswordGenerator_ConfiguresInstance() {
            var appConfig = @"<?xml version='1.0'?>
                <configuration>
                    <configSections>
                        <section name='ensues.security' type='Ensues.Configuration.SecuritySection, Ensues.Security' />
                    </configSections>
                    <ensues.security>
                        <passwordAlgorithm hashFunction='SHA384' hashIterations='123456' compareInConstantTime='false' saltLength='321' />
                        <passwordGenerator length='100' symbols='abcdefghijklmnopqrstuvwxyz' />
                    </ensues.security>
                </configuration>
            ";
            using (AppConfig.With(appConfig)) {
                var gen = new PasswordGenerator();
                SecurityConfiguration.Default.ConfigurePasswordGenerator(gen);
                Assert.AreEqual(100, gen.Length);
                Assert.AreEqual("abcdefghijklmnopqrstuvwxyz", gen.Symbols);
            }
        }
    }
}
