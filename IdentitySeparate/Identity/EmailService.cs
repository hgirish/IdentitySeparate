using Microsoft.AspNet.Identity;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace IdentitySeparate.Identity
{
    public class EmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            var client = new SmtpClient
            {
                Host = "smtphost",
                Port = 2525,
                Credentials = new NetworkCredential("username", "password"),
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.SpecifiedPickupDirectory,
                PickupDirectoryLocation = "C:\\Temp\\MailBox"
            };

            var @from = new MailAddress("no-reply@tech.trailmax.info", "My Awesome Admin");
            var to = new MailAddress(message.Destination);

            var mail = new MailMessage(@from, to)
            {
                Subject = message.Subject,
                Body = message.Body,
                IsBodyHtml = true,
            };

            client.Send(mail);

            return Task.FromResult(0);
        }
    }
}