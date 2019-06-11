using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MiniBlogElasticsearch.Models;
using Nest;
using System;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MiniBlogElasticsearch.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private IConfiguration _config;
        private IElasticClient _elasticClient;

        ILogger<AccountController> _logger;
        
        public AccountController(IConfiguration config, IElasticClient elasticClient, ILogger<AccountController> logger)
        {
            _config = config;
            _elasticClient = elasticClient;
            _logger = logger;
        }
        
        [Route("/login")]
        [HttpPost, AllowAnonymous, ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginAsync(string returnUrl, LoginViewModel model)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid && model.UserName == _config["user:username"] && VerifyHashedPassword(model.Password, _config))
            {
                var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
                identity.AddClaim(new Claim(ClaimTypes.Name, _config["user:username"]));

                var principle = new ClaimsPrincipal(identity);
                var properties = new AuthenticationProperties { IsPersistent = model.RememberMe };
                await HttpContext.SignInAsync(principle, properties);

                return LocalRedirect(returnUrl ?? "/");
            }

            ModelState.AddModelError(string.Empty, "Username or password is invalid.");
            return View("login", model);
        }

        [Route("/logout")]
        public async Task<IActionResult> LogOutAsync()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return LocalRedirect("/");
        }

        [NonAction]
        internal static bool VerifyHashedPassword(string password, IConfiguration config)
        {
            byte[] saltBytes = Encoding.UTF8.GetBytes(config["user:salt"]);

            byte[] hashBytes = KeyDerivation.Pbkdf2(
                password: password,
                salt: saltBytes,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 1000,
                numBytesRequested: 256 / 8
            );

            string hashText = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
            return hashText == config["user:password"];
        }

        [Route("/login")]
        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            LogTesting l = new LogTesting()
            {
                Date = DateTime.Now,
                User = "Itiro",
                Exception = new Exception("Exception test"),
                Method = MethodBase.GetCurrentMethod().Name
            };

            await _elasticClient.IndexDocumentAsync(l);

            _logger.LogInformation($"oh hai there! : {DateTime.UtcNow}");

            try
            {
                throw new Exception("oops. i haz cause error in UR codez.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ur code iz buggy.");
            }


            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

    }

    public class LogTesting
    {
        public DateTime Date { get; set; }
        public String User { get; set; }
        public Exception Exception { get; set; }
        public String Method { get; set; }
    }
}
