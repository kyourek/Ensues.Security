using System;
using System.Configuration;

using Ensues.Security.Cryptography;
namespace Ensues.Configuration {
    internal class SecurityConfiguration {
        private SecuritySection Section {
            get { return _Section ?? (_Section = ConfigurationManager.GetSection(SectionName) as SecuritySection); }
        }
        private SecuritySection _Section;

        protected SecurityConfiguration() { }

        public const string SectionName = "ensues.security";

        public static SecurityConfiguration Default { get { return _Default; } }
        private static readonly SecurityConfiguration _Default = new SecurityConfiguration();

        public void ConfigurePasswordAlgorithm(PasswordAlgorithm passwordAlgorithm) {
            var element = Section;
            if (element != null) {
                var elementInformation = element.ElementInformation;
                if (elementInformation != null && elementInformation.IsPresent) {
                    element.ConfigurePasswordAlgorithm(passwordAlgorithm);
                }
            }
        }
    }
}
