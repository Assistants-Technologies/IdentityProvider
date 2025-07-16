using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using System.Web;
using Infra.Modules.IdentityProvider.Data.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace Infra.Modules.IdentityProvider.Pages
{
    public class RegisterModel : PageModel 
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IOpenIddictApplicationManager _apps;

        public RegisterModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IOpenIddictApplicationManager apps)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _apps = apps;
            CountryList = GetAllCountries();
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public string ReturnUrl { get; set; } = "/";

        public string? ApplicationName { get; private set; }

        [TempData]
        public string ErrorMessage { get; set; } = string.Empty;

        public List<CountryInfo> CountryList { get; }

        public class InputModel
        {
            [Required, EmailAddress]
            public string Email { get; set; } = string.Empty;

            [Required]
            [StringLength(20, MinimumLength = 3)]
            [RegularExpression(@"^[a-zA-Z0-9_-]+$", 
                ErrorMessage = "Username can only contain letters, numbers, underscores and hyphens")]
            public string UserName { get; set; } = string.Empty;

            [Required]
            public string Country { get; set; } = string.Empty;

            [Required, DataType(DataType.Password)]
            public string Password { get; set; } = string.Empty;

            [Required, DataType(DataType.Password)]
            [Compare("Password", ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; } = string.Empty;
        }

        public class CountryInfo
        {
            public string Code { get; set; } = string.Empty;
            public string Name { get; set; } = string.Empty;
        }

        public async Task OnGetAsync(string? returnUrl = null)
        {
            if (!string.IsNullOrEmpty(returnUrl))
            {
                ReturnUrl = returnUrl;
                Response.Cookies.Append("returnUrl", ReturnUrl);
            }
            else
            {
                Request.Cookies.TryGetValue("returnUrl", out var saved);
                ReturnUrl = !string.IsNullOrEmpty(saved) ? saved! : Url.Content("~/");
            }

            if (!string.IsNullOrEmpty(ErrorMessage))
                ModelState.AddModelError(string.Empty, ErrorMessage);

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            var uri = new Uri(Request.Scheme + "://" + Request.Host + ReturnUrl);
            var qs = HttpUtility.ParseQueryString(uri.Query);
            var clientId = qs["client_id"];
            if (!string.IsNullOrEmpty(clientId))
            {
                var desc = await _apps.FindByClientIdAsync(clientId);
                if (desc != null)
                    ApplicationName = await _apps.GetDisplayNameAsync(desc);
            }
        }

        public async Task<IActionResult> OnPostRegisterAsync(string? returnUrl = null)
        {
            ReturnUrl = returnUrl ?? Url.Content("~/");

            if (!ModelState.IsValid)
                return Page();

            if (!IsValidUsername(Input.UserName))
            {
                ModelState.AddModelError(nameof(Input.UserName), 
                    "Username contains invalid characters");
                return Page();
            }

            var user = new ApplicationUser 
            { 
                UserName = Input.UserName,
                Email = Input.Email,
                Country = Input.Country
            };

            var result = await _userManager.CreateAsync(user, Input.Password);

            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return LocalRedirect(ReturnUrl);
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return Page();
        }

        private bool IsValidUsername(string username)
        {
            return Regex.IsMatch(username, @"^[a-zA-Z0-9_-]+$");
        }

        private static List<CountryInfo> GetAllCountries()
        {
            return new List<CountryInfo>
            {
                new CountryInfo { Code="AF", Name="Afghanistan" },
                new CountryInfo { Code="AX", Name="Åland Islands" },
                new CountryInfo { Code="AL", Name="Albania" },
                new CountryInfo { Code="DZ", Name="Algeria" },
                new CountryInfo { Code="AS", Name="American Samoa" },
                new CountryInfo { Code="AD", Name="Andorra" },
                new CountryInfo { Code="AO", Name="Angola" },
                new CountryInfo { Code="AI", Name="Anguilla" },
                new CountryInfo { Code="AQ", Name="Antarctica" },
                new CountryInfo { Code="AG", Name="Antigua and Barbuda" },
                new CountryInfo { Code="AR", Name="Argentina" },
                new CountryInfo { Code="AM", Name="Armenia" },
                new CountryInfo { Code="AW", Name="Aruba" },
                new CountryInfo { Code="AU", Name="Australia" },
                new CountryInfo { Code="AT", Name="Austria" },
                new CountryInfo { Code="AZ", Name="Azerbaijan" },
                new CountryInfo { Code="BS", Name="Bahamas" },
                new CountryInfo { Code="BH", Name="Bahrain" },
                new CountryInfo { Code="BD", Name="Bangladesh" },
                new CountryInfo { Code="BB", Name="Barbados" },
                new CountryInfo { Code="BY", Name="Belarus" },
                new CountryInfo { Code="BE", Name="Belgium" },
                new CountryInfo { Code="BZ", Name="Belize" },
                new CountryInfo { Code="BJ", Name="Benin" },
                new CountryInfo { Code="BM", Name="Bermuda" },
                new CountryInfo { Code="BT", Name="Bhutan" },
                new CountryInfo { Code="BO", Name="Bolivia" },
                new CountryInfo { Code="BQ", Name="Bonaire, Sint Eustatius and Saba" },
                new CountryInfo { Code="BA", Name="Bosnia and Herzegovina" },
                new CountryInfo { Code="BW", Name="Botswana" },
                new CountryInfo { Code="BV", Name="Bouvet Island" },
                new CountryInfo { Code="BR", Name="Brazil" },
                new CountryInfo { Code="IO", Name="British Indian Ocean Territory" },
                new CountryInfo { Code="BN", Name="Brunei Darussalam" },
                new CountryInfo { Code="BG", Name="Bulgaria" },
                new CountryInfo { Code="BF", Name="Burkina Faso" },
                new CountryInfo { Code="BI", Name="Burundi" },
                new CountryInfo { Code="CV", Name="Cabo Verde" },
                new CountryInfo { Code="KH", Name="Cambodia" },
                new CountryInfo { Code="CM", Name="Cameroon" },
                new CountryInfo { Code="CA", Name="Canada" },
                new CountryInfo { Code="KY", Name="Cayman Islands" },
                new CountryInfo { Code="CF", Name="Central African Republic" },
                new CountryInfo { Code="TD", Name="Chad" },
                new CountryInfo { Code="CL", Name="Chile" },
                new CountryInfo { Code="CN", Name="China" },
                new CountryInfo { Code="CX", Name="Christmas Island" },
                new CountryInfo { Code="CC", Name="Cocos (Keeling) Islands" },
                new CountryInfo { Code="CO", Name="Colombia" },
                new CountryInfo { Code="KM", Name="Comoros" },
                new CountryInfo { Code="CG", Name="Congo" },
                new CountryInfo { Code="CD", Name="Congo, Democratic Republic of the" },
                new CountryInfo { Code="CK", Name="Cook Islands" },
                new CountryInfo { Code="CR", Name="Costa Rica" },
                new CountryInfo { Code="CI", Name="Côte d'Ivoire" },
                new CountryInfo { Code="HR", Name="Croatia" },
                new CountryInfo { Code="CU", Name="Cuba" },
                new CountryInfo { Code="CW", Name="Curaçao" },
                new CountryInfo { Code="CY", Name="Cyprus" },
                new CountryInfo { Code="CZ", Name="Czechia" },
                new CountryInfo { Code="DK", Name="Denmark" },
                new CountryInfo { Code="DJ", Name="Djibouti" },
                new CountryInfo { Code="DM", Name="Dominica" },
                new CountryInfo { Code="DO", Name="Dominican Republic" },
                new CountryInfo { Code="EC", Name="Ecuador" },
                new CountryInfo { Code="EG", Name="Egypt" },
                new CountryInfo { Code="SV", Name="El Salvador" },
                new CountryInfo { Code="GQ", Name="Equatorial Guinea" },
                new CountryInfo { Code="ER", Name="Eritrea" },
                new CountryInfo { Code="EE", Name="Estonia" },
                new CountryInfo { Code="SZ", Name="Eswatini" },
                new CountryInfo { Code="ET", Name="Ethiopia" },
                new CountryInfo { Code="FK", Name="Falkland Islands (Malvinas)" },
                new CountryInfo { Code="FO", Name="Faroe Islands" },
                new CountryInfo { Code="FJ", Name="Fiji" },
                new CountryInfo { Code="FI", Name="Finland" },
                new CountryInfo { Code="FR", Name="France" },
                new CountryInfo { Code="GF", Name="French Guiana" },
                new CountryInfo { Code="PF", Name="French Polynesia" },
                new CountryInfo { Code="TF", Name="French Southern Territories" },
                new CountryInfo { Code="GA", Name="Gabon" },
                new CountryInfo { Code="GM", Name="Gambia" },
                new CountryInfo { Code="GE", Name="Georgia" },
                new CountryInfo { Code="DE", Name="Germany" },
                new CountryInfo { Code="GH", Name="Ghana" },
                new CountryInfo { Code="GI", Name="Gibraltar" },
                new CountryInfo { Code="GR", Name="Greece" },
                new CountryInfo { Code="GL", Name="Greenland" },
                new CountryInfo { Code="GD", Name="Grenada" },
                new CountryInfo { Code="GP", Name="Guadeloupe" },
                new CountryInfo { Code="GU", Name="Guam" },
                new CountryInfo { Code="GT", Name="Guatemala" },
                new CountryInfo { Code="GG", Name="Guernsey" },
                new CountryInfo { Code="GN", Name="Guinea" },
                new CountryInfo { Code="GW", Name="Guinea-Bissau" },
                new CountryInfo { Code="GY", Name="Guyana" },
                new CountryInfo { Code="HT", Name="Haiti" },
                new CountryInfo { Code="HM", Name="Heard Island and McDonald Islands" },
                new CountryInfo { Code="VA", Name="Holy See" },
                new CountryInfo { Code="HN", Name="Honduras" },
                new CountryInfo { Code="HK", Name="Hong Kong" },
                new CountryInfo { Code="HU", Name="Hungary" },
                new CountryInfo { Code="IS", Name="Iceland" },
                new CountryInfo { Code="IN", Name="India" },
                new CountryInfo { Code="ID", Name="Indonesia" },
                new CountryInfo { Code="IR", Name="Iran (Islamic Republic of)" },
                new CountryInfo { Code="IQ", Name="Iraq" },
                new CountryInfo { Code="IE", Name="Ireland" },
                new CountryInfo { Code="IM", Name="Isle of Man" },
                new CountryInfo { Code="IL", Name="Israel" },
                new CountryInfo { Code="IT", Name="Italy" },
                new CountryInfo { Code="JM", Name="Jamaica" },
                new CountryInfo { Code="JP", Name="Japan" },
                new CountryInfo { Code="JE", Name="Jersey" },
                new CountryInfo { Code="JO", Name="Jordan" },
                new CountryInfo { Code="KZ", Name="Kazakhstan" },
                new CountryInfo { Code="KE", Name="Kenya" },
                new CountryInfo { Code="KI", Name="Kiribati" },
                new CountryInfo { Code="KP", Name="Korea (Democratic People's Republic of)" },
                new CountryInfo { Code="KR", Name="Korea, Republic of" },
                new CountryInfo { Code="KW", Name="Kuwait" },
                new CountryInfo { Code="KG", Name="Kyrgyzstan" },
                new CountryInfo { Code="LA", Name="Lao People's Democratic Republic" },
                new CountryInfo { Code="LV", Name="Latvia" },
                new CountryInfo { Code="LB", Name="Lebanon" },
                new CountryInfo { Code="LS", Name="Lesotho" },
                new CountryInfo { Code="LR", Name="Liberia" },
                new CountryInfo { Code="LY", Name="Libya" },
                new CountryInfo { Code="LI", Name="Liechtenstein" },
                new CountryInfo { Code="LT", Name="Lithuania" },
                new CountryInfo { Code="LU", Name="Luxembourg" },
                new CountryInfo { Code="MO", Name="Macao" },
                new CountryInfo { Code="MG", Name="Madagascar" },
                new CountryInfo { Code="MW", Name="Malawi" },
                new CountryInfo { Code="MY", Name="Malaysia" },
                new CountryInfo { Code="MV", Name="Maldives" },
                new CountryInfo { Code="ML", Name="Mali" },
                new CountryInfo { Code="MT", Name="Malta" },
                new CountryInfo { Code="MH", Name="Marshall Islands" },
                new CountryInfo { Code="MQ", Name="Martinique" },
                new CountryInfo { Code="MR", Name="Mauritania" },
                new CountryInfo { Code="MU", Name="Mauritius" },
                new CountryInfo { Code="YT", Name="Mayotte" },
                new CountryInfo { Code="MX", Name="Mexico" },
                new CountryInfo { Code="FM", Name="Micronesia (Federated States of)" },
                new CountryInfo { Code="MD", Name="Moldova, Republic of" },
                new CountryInfo { Code="MC", Name="Monaco" },
                new CountryInfo { Code="MN", Name="Mongolia" },
                new CountryInfo { Code="ME", Name="Montenegro" },
                new CountryInfo { Code="MS", Name="Montserrat" },
                new CountryInfo { Code="MA", Name="Morocco" },
                new CountryInfo { Code="MZ", Name="Mozambique" },
                new CountryInfo { Code="MM", Name="Myanmar" },
                new CountryInfo { Code="NA", Name="Namibia" },
                new CountryInfo { Code="NR", Name="Nauru" },
                new CountryInfo { Code="NP", Name="Nepal" },
                new CountryInfo { Code="NL", Name="Netherlands" },
                new CountryInfo { Code="NC", Name="New Caledonia" },
                new CountryInfo { Code="NZ", Name="New Zealand" },
                new CountryInfo { Code="NI", Name="Nicaragua" },
                new CountryInfo { Code="NE", Name="Niger" },
                new CountryInfo { Code="NG", Name="Nigeria" },
                new CountryInfo { Code="NU", Name="Niue" },
                new CountryInfo { Code="NF", Name="Norfolk Island" },
                new CountryInfo { Code="MK", Name="North Macedonia" },
                new CountryInfo { Code="MP", Name="Northern Mariana Islands" },
                new CountryInfo { Code="NO", Name="Norway" },
                new CountryInfo { Code="OM", Name="Oman" },
                new CountryInfo { Code="PK", Name="Pakistan" },
                new CountryInfo { Code="PW", Name="Palau" },
                new CountryInfo { Code="PS", Name="Palestine, State of" },
                new CountryInfo { Code="PA", Name="Panama" },
                new CountryInfo { Code="PG", Name="Papua New Guinea" },
                new CountryInfo { Code="PY", Name="Paraguay" },
                new CountryInfo { Code="PE", Name="Peru" },
                new CountryInfo { Code="PH", Name="Philippines" },
                new CountryInfo { Code="PN", Name="Pitcairn" },
                new CountryInfo { Code="PL", Name="Poland" },
                new CountryInfo { Code="PT", Name="Portugal" },
                new CountryInfo { Code="PR", Name="Puerto Rico" },
                new CountryInfo { Code="QA", Name="Qatar" },
                new CountryInfo { Code="RE", Name="Réunion" },
                new CountryInfo { Code="RO", Name="Romania" },
                new CountryInfo { Code="RU", Name="Russian Federation" },
                new CountryInfo { Code="RW", Name="Rwanda" },
                new CountryInfo { Code="BL", Name="Saint Barthélemy" },
                new CountryInfo { Code="SH", Name="Saint Helena, Ascension and Tristan da Cunha" },
                new CountryInfo { Code="KN", Name="Saint Kitts and Nevis" },
                new CountryInfo { Code="LC", Name="Saint Lucia" },
                new CountryInfo { Code="MF", Name="Saint Martin (French part)" },
                new CountryInfo { Code="PM", Name="Saint Pierre and Miquelon" },
                new CountryInfo { Code="VC", Name="Saint Vincent and the Grenadines" },
                new CountryInfo { Code="WS", Name="Samoa" },
                new CountryInfo { Code="SM", Name="San Marino" },
                new CountryInfo { Code="ST", Name="Sao Tome and Principe" },
                new CountryInfo { Code="SA", Name="Saudi Arabia" },
                new CountryInfo { Code="SN", Name="Senegal" },
                new CountryInfo { Code="RS", Name="Serbia" },
                new CountryInfo { Code="SC", Name="Seychelles" },
                new CountryInfo { Code="SL", Name="Sierra Leone" },
                new CountryInfo { Code="SG", Name="Singapore" },
                new CountryInfo { Code="SX", Name="Sint Maarten (Dutch part)" },
                new CountryInfo { Code="SK", Name="Slovakia" },
                new CountryInfo { Code="SI", Name="Slovenia" },
                new CountryInfo { Code="SB", Name="Solomon Islands" },
                new CountryInfo { Code="SO", Name="Somalia" },
                new CountryInfo { Code="ZA", Name="South Africa" },
                new CountryInfo { Code="GS", Name="South Georgia and the South Sandwich Islands" },
                new CountryInfo { Code="SS", Name="South Sudan" },
                new CountryInfo { Code="ES", Name="Spain" },
                new CountryInfo { Code="LK", Name="Sri Lanka" },
                new CountryInfo { Code="SD", Name="Sudan" },
                new CountryInfo { Code="SR", Name="Suriname" },
                new CountryInfo { Code="SJ", Name="Svalbard and Jan Mayen" },
                new CountryInfo { Code="SE", Name="Sweden" },
                new CountryInfo { Code="CH", Name="Switzerland" },
                new CountryInfo { Code="SY", Name="Syrian Arab Republic" },
                new CountryInfo { Code="TW", Name="Taiwan, Province of China" },
                new CountryInfo { Code="TJ", Name="Tajikistan" },
                new CountryInfo { Code="TZ", Name="Tanzania, United Republic of" },
                new CountryInfo { Code="TH", Name="Thailand" },
                new CountryInfo { Code="TL", Name="Timor-Leste" },
                new CountryInfo { Code="TG", Name="Togo" },
                new CountryInfo { Code="TK", Name="Tokelau" },
                new CountryInfo { Code="TO", Name="Tonga" },
                new CountryInfo { Code="TT", Name="Trinidad and Tobago" },
                new CountryInfo { Code="TN", Name="Tunisia" },
                new CountryInfo { Code="TR", Name="Turkey" },
                new CountryInfo { Code="TM", Name="Turkmenistan" },
                new CountryInfo { Code="TC", Name="Turks and Caicos Islands" },
                new CountryInfo { Code="TV", Name="Tuvalu" },
                new CountryInfo { Code="UG", Name="Uganda" },
                new CountryInfo { Code="UA", Name="Ukraine" },
                new CountryInfo { Code="AE", Name="United Arab Emirates" },
                new CountryInfo { Code="GB", Name="United Kingdom of Great Britain and Northern Ireland" },
                new CountryInfo { Code="US", Name="United States of America" },
                new CountryInfo { Code="UM", Name="United States Minor Outlying Islands" },
                new CountryInfo { Code="UY", Name="Uruguay" },
                new CountryInfo { Code="UZ", Name="Uzbekistan" },
                new CountryInfo { Code="VU", Name="Vanuatu" },
                new CountryInfo { Code="VE", Name="Venezuela (Bolivarian Republic of)" },
                new CountryInfo { Code="VN", Name="Viet Nam" },
                new CountryInfo { Code="VG", Name="Virgin Islands (British)" },
                new CountryInfo { Code="VI", Name="Virgin Islands (U.S.)" },
                new CountryInfo { Code="WF", Name="Wallis and Futuna" },
                new CountryInfo { Code="EH", Name="Western Sahara" },
                new CountryInfo { Code="YE", Name="Yemen" },
                new CountryInfo { Code="ZM", Name="Zambia" },
                new CountryInfo { Code="ZW", Name="Zimbabwe" }
            };
        }
    }
}