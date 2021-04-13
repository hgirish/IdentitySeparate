using IdentitySeparate.Data.EntityFramework;
using IdentitySeparate.Domain;
using IdentitySeparate.Identity;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System;
using System.Web;
using System.Web.Mvc;
using Unity;
using Unity.Injection;
using Unity.Lifetime;
using Unity.Mvc5;


namespace IdentitySeparate
{
    public static class UnityConfig
    {
        public static void RegisterComponents()
        {
			var container = new UnityContainer();
            container.RegisterFactory<IAuthenticationManager>(           
                o => HttpContext.Current.GetOwinContext().Authentication);
            container.RegisterType<IUnitOfWork, UnitOfWork>(new HierarchicalLifetimeManager(), new InjectionConstructor("IdentitySeparate"));
            container.RegisterType<IUserStore<ApplicationUser,string>, UserStore>(new TransientLifetimeManager());
            container.RegisterType<IUserStore<ApplicationUser>, UserStore>(new TransientLifetimeManager());
            container.RegisterType<ApplicationUserManager>(new HierarchicalLifetimeManager());

            container.RegisterType<ApplicationDbContext>();
            //container.RegisterType<ApplicationSignInManager>();
            container.RegisterType<ApplicationUserManager>();
            //container.RegisterType<ApplicationRoleManager>();

            container.RegisterType<IIdentityMessageService, EmailService>("production");
            //container.RegisterType<IIdentityMessageService, MailtrapEmailService>("debugging");


            container.RegisterType<RoleStore>(new TransientLifetimeManager());
            container.RegisterType<SignInManager<ApplicationUser,string>>();

            DependencyResolver.SetResolver(new UnityDependencyResolver(container));
        }
    }
}