using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace InternetBankingRESTfulService.Tests
{
    /// <summary>
    /// !!! WARNING 
    /// !!! Project structure test
    /// !!! DON'T CHANGE IT! 
    /// !!! Changes may cause the solution to be rejected.
    /// </summary>
    [TestClass]
    public class StructureReadonlyTest
    {
        /// <summary>
        /// !!! WARNING 
        /// !!! Project structure test.
        /// !!! DON'T CHANGE IT! 
        /// !!! Changes may cause the solution to be rejected.
        /// </summary>
        [TestMethod]
        public void TestStructure()
        {
            var assemblyApi = Assembly.Load(Decode("SW50ZXJuZXRCYW5raW5nUkVTVGZ1bFNlcnZpY2UuQXBp"));
            Assert.IsNotNull(assemblyApi, "Missing: InternetBankingRESTfulService.Api");

            Type internetBankingApi = assemblyApi.GetTypes().FirstOrDefault(a => a.Name == Decode("SUludGVybmV0QmFua2luZ0FwaQ=="));
            Assert.IsNotNull(internetBankingApi, "Missing: IInternetBankingApi");
            Assert.IsTrue(internetBankingApi.IsPublic && internetBankingApi.IsInterface && !internetBankingApi.GetInterfaces().Any(), "Incorrect: IInternetBankingApi");
            Assert.AreEqual(3, internetBankingApi.GetMethods().Count(), "Incorrect: IInternetBankingApi");
            Assert.IsTrue(internetBankingApi.GetMethods().Any(a => a.Name == Decode("R2V0QXBpVmVyc2lvbg==") && a.ReturnType == typeof(string) && !a.GetParameters().Any()), "Incorrect: IInternetBankingApi");
            Assert.IsTrue(internetBankingApi.GetMethods().Any(a => a.Name == Decode("Q2FsY3VsYXRlTUQ1") && a.ReturnType == typeof(string) && a.GetParameters().All(p => p.ParameterType == typeof(string))), "Incorrect: IInternetBankingApi");
            Assert.IsTrue(internetBankingApi.GetMethods().Any(a => a.Name == Decode("SXNQYXNzd29yZFN0cm9uZw==") && a.ReturnType == typeof(bool) && a.GetParameters().All(p => p.ParameterType == typeof(string))), "Incorrect: IInternetBankingApi");

            var assembly = Assembly.Load(Decode("SW50ZXJuZXRCYW5raW5nUkVTVGZ1bFNlcnZpY2UuV2Vi"));
            Assert.IsNotNull(assembly, "Missing: InternetBankingRESTfulService.Web");
            Type startup = assembly.GetTypes().FirstOrDefault(a => a.Name == Decode("U3RhcnR1cA=="));
            Assert.IsNotNull(startup, "Missing: Startup");

            Assert.IsTrue(startup.GetMethods().Any(a => a.IsPublic && a.Name == Decode("Q29uZmlndXJlU2VydmljZXM=") && a.ReturnType == typeof(void) && a.GetParameters().All(p => p.ParameterType.Name == Decode("SVNlcnZpY2VDb2xsZWN0aW9u"))), "Incorrect: Startup");
            Assert.IsTrue(startup.GetMethods().Any(a => a.IsPublic && a.Name == Decode("Q29uZmlndXJl") && a.ReturnType == typeof(void) && a.GetParameters().Count()==2 &&
                a.GetParameters().Any(p => p.ParameterType.Name == Decode("SUFwcGxpY2F0aW9uQnVpbGRlcg==")) &&
                a.GetParameters().Any(p => p.ParameterType.Name == Decode("SVdlYkhvc3RFbnZpcm9ubWVudA=="))), "Incorrect: Startup");


            Type program = assembly.GetTypes().FirstOrDefault(a => a.Name == Decode("UHJvZ3JhbQ=="));
            Assert.IsNotNull(program, "Missing: Program");
        }

        /// <summary>
        /// !!! WARNING 
        /// !!! Project structure test.
        /// !!! DON'T CHANGE IT! 
        /// !!! Changes may cause the solution to be rejected.
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        private string Decode(string text)
        {
            return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(text));
        }
    }
}
