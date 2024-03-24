using Microsoft.AspNetCore.Mvc;
using System;

namespace TFSport.API.Filters
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class CustomExceptionFilterAttribute : TypeFilterAttribute
    {
        public CustomExceptionFilterAttribute()
            : base(typeof(CustomExceptionFilter))
        {
        }
    }
}
