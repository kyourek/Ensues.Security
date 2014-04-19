using System;
using System.Configuration;

namespace Ensues.Configuration {

    internal class SecurityConfiguration {

        private SecuritySection Section {
            get {
                return _Section ?? (_Section = ConfigurationManager.GetSection(SectionName) as SecuritySection);
            }
        }
        private SecuritySection _Section;

        protected internal SecurityConfiguration() { }

        public static SecurityConfiguration Default { get { return _Default; } }
        private static readonly SecurityConfiguration _Default = new SecurityConfiguration();

        public string SectionName {
            get { return _SectionName ?? (_SectionName = "ensues.security"); }
            set { _SectionName = value; }
        }
        private string _SectionName;

        public IPasswordAlgorithmConfiguration PasswordAlgorithmConfiguration {
            get {
                if (_PasswordAlgorithmConfiguration == null) {

                    var section = Section;
                    if (section != null) {
                        _PasswordAlgorithmConfiguration = section.PasswordAlgorithm;
                    }
                }

                return _PasswordAlgorithmConfiguration;
            }
        }
        private IPasswordAlgorithmConfiguration _PasswordAlgorithmConfiguration;
    }
}
