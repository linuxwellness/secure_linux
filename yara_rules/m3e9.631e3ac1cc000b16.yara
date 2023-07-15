
rule m3e9_631e3ac1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631e3ac1cc000b16"
     cluster="m3e9.631e3ac1cc000b16"
     cluster_size="323"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack virut"
     md5_hashes="['053469cd026cc121507fc20d8b9ae832','055dff73fae540e0a7692e6a4e47f979','1b446cdcd41fce469d9320756f0539c0']"

   strings:
      $hex_string = { 0cfa4d6a8edacf4a10bb512b929bd30b147c55ec965cd7cc183d59ad9a1ddb8d1cfe5d6e9ededf4e20bf612fa29fe30f248065f0a660e7d0284169b1aa21eb91 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
