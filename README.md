# IdentitySeparate
ASP.NET MVC Identity in separate project, inspired by https://github.com/timschreiber/Mvc5IdentityExample




Enable-Migrations -ContextTypeName ApplicationDbContext -ProjectName IdentitySeparate.Data.EntityFramework -ConnectionStringName IdentitySeparate

Add-Migration -Name Identity  -ProjectName IdentitySeparate.Data.EntityFramework -ConnectionStringName IdentitySeparate

update-database -ProjectName IdentitySeparate.Data.EntityFramework
