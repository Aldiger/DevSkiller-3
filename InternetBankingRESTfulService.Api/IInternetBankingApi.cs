using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace InternetBankingRESTfulService.Api
{
    public interface IInternetBankingApi
    {
        string GetApiVersion();
        string CalculateMD5(string value);
        bool IsPasswordStrong(string password);
    }
}
