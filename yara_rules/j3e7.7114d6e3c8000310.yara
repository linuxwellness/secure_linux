
rule j3e7_7114d6e3c8000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7114d6e3c8000310"
     cluster="j3e7.7114d6e3c8000310"
     cluster_size="152"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['0303b42c9a2c500ff5ec298701ea4321','053215dad3c3830a0e608558f782c191','1388499338199f780b3a9a3d77ff04b8']"

   strings:
      $hex_string = { 616e672f436c6173733b00135b4c6a6176612f6c616e672f4f626a6563743b000161001a616e64726f69642e6170702e41637469766974795468726561640026 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
