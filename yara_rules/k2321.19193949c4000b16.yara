
rule k2321_19193949c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.19193949c4000b16"
     cluster="k2321.19193949c4000b16"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['2acab71349d33433ac5b442afa6ac73c','59847595d5b6f7c6b82220ebe57b93f1','e3702aa8e7a3189e27d6eedade4bde08']"

   strings:
      $hex_string = { 067b1657452edf2c2a6d9a95e9bee774d46f02581f83d5fdf0f2a3c127ba798717474eb29ff5cadef5770ad978eacc46dbbc3193946b827f2b9de3325980edf3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
