using System;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Reflection;

namespace Ensues.Configuration {
    internal abstract class AppConfig : IDisposable {
        protected virtual void Dispose(bool disposing) {
        }

        public static AppConfig Change(string path) {
            return new ChangeAppConfig(path);
        }

        public static AppConfig With(string contents) {
            return new WithAppConfig(contents);
        }

        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~AppConfig() {
            Dispose(false);
        }

        private class ChangeAppConfig : AppConfig {
            private readonly string OldConfig = AppDomain.CurrentDomain.GetData("APP_CONFIG_FILE").ToString();

            protected override void Dispose(bool disposing) {
                if (disposing) {
                    AppDomain.CurrentDomain.SetData("APP_CONFIG_FILE", OldConfig);
                    ResetConfigMechanism();
                }
                base.Dispose(disposing);
            }

            public string Path { get { return _Path; } }
            private readonly string _Path;

            public ChangeAppConfig(string path) {
                _Path = path;
                AppDomain.CurrentDomain.SetData("APP_CONFIG_FILE", _Path);
                ResetConfigMechanism();
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

        private class WithAppConfig : ChangeAppConfig {
            private static string GetPath(string contents) {
                var path = System.IO.Path.GetTempFileName();
                File.WriteAllText(path, contents);
                return path;
            }

            protected override void Dispose(bool disposing) {
                base.Dispose(disposing);
                if (disposing) {
                    var path = Path;
                    if (File.Exists(path)) {
                        File.Delete(path);
                    }
                }
            }

            public WithAppConfig(string contents) : base(GetPath(contents)) {
            }
        }
    }
}
