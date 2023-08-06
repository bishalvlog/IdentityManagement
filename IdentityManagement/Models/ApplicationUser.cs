﻿using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Rendering;
using NuGet.Protocol;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityManagement.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        public string Name { get; set; }
        [NotMapped]
        public string RoleId { get; set; }
        [NotMapped]
        public string Role { get; set; }
        [NotMapped]
        public IEnumerable<SelectListItem> RoleList { get;set;  }
    }
}
