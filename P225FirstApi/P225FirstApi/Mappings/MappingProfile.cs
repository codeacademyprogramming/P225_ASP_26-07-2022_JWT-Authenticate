using AutoMapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using P225FirstApi.DTOs.CategoryDTOs;
using P225FirstApi.Data.Entities;
using P225FirstApi.DTOs.AccountsDTOs;

namespace P225FirstApi.Mappings
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            #region Category
            CreateMap<CategoryPostDto, Category>()
                .ForMember(des => des.Name, src => src.MapFrom(s => s.Ad.Trim()))
                .ForMember(des => des.IsMain, src => src.MapFrom(s => s.Esasdirmi))
                .ForMember(des => des.ParentId, src => src.MapFrom(s => s.Esasdirmi ? null : s.AidOlduguKategoriyaninIdsi))
                .ForMember(des => des.Image, src => src.MapFrom(s => s.Esasdirmi ? s.Sekil : null))
                .ForMember(des => des.CreatedAt, src => DateTime.UtcNow.AddHours(4));

            CreateMap<Category, CategoryListDto>()
                .ForMember(des => des.Ad, src => src.MapFrom(s => s.Name));

            CreateMap<Category, CategoryGetDto>()
                .ForMember(des => des.Ad, src => src.MapFrom(s => s.Name))
                .ForMember(des => des.Sekil, src => src.MapFrom(s => s.Image))
                .ForMember(des => des.Esasdirmi, src => src.MapFrom(s => s.IsMain))
                .ForMember(des => des.AidOlduguKategoriyaninIdsi, src => src.MapFrom(s => s.ParentId));

            CreateMap<CategoryPutDto, Category>()
                .ForMember(des => des.Name, src => src.MapFrom(s => s.Ad.Trim()))
                .ForMember(des => des.IsMain, src => src.MapFrom(s => s.Esasdirmi))
                .ForMember(des => des.ParentId, src => src.MapFrom(s => s.Esasdirmi ? null : s.AidOlduguKategoriyaninIdsi))
                .ForMember(des => des.Image, src => src.MapFrom(s => s.Esasdirmi ? s.Sekil : null))
                .ForMember(des => des.UpdatedAt, src => DateTime.UtcNow.AddHours(4));
            #endregion

            CreateMap<RegisterDto, AppUser>();
        }
    }
}
