using System;
using System.Configuration;
using System.Linq;
using System.Reflection;

namespace Ensues.Configuration {
    internal abstract class AlternateAppConfig : IDisposable {
        public static AlternateAppConfig Change(string path) {
            return new ChangeAppConfig(path);
        }

        public abstract void Dispose();

        private class ChangeAppConfig : AlternateAppConfig {
            private readonly string OldConfig = AppDomain.CurrentDomain.GetData("APP_CONFIG_FILE").ToString();
            private bool DisposedValue;

            public ChangeAppConfig(string path) {
                AppDomain.CurrentDomain.SetData("APP_CONFIG_FILE", path);
                ResetConfigMechanism();
            }

            public override void Dispose() {
                if (!DisposedValue) {
                    AppDomain.CurrentDomain.SetData("APP_CONFIG_FILE", OldConfig);
                    ResetConfigMechanism();
                    DisposedValue = true;
                }
                GC.SuppressFinalize(this);
            }

            private static void ResetConfigMechanism() {
                typeof(ConfigurationManager)
                    .GetField("s_initState", BindingFlags.NonPublic | BindingFlags.Static)
                    .SetValue(null, 0);

                typeof(ConfigurationManager)
                    .GetField("s_configSystem", BindingFlags.NonPublic | BindingFlags.Static)
                    .SetValue(null, null);

                typeof(ConfigurationManager)
                    .Assembly
                    .GetTypes()
                    .Where(x => x.FullName == "System.Configuration.ClientConfigPaths")
                    .First()
                    .GetField("s_current", BindingFlags.NonPublic | BindingFlags.Static)
                    .SetValue(null, null);
            }
        }
    }
}
