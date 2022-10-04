using System.Threading.Tasks;

namespace MicrosoftTeams
{
    public interface IPassword
    {
        Task<string> GetToken();
    }
}