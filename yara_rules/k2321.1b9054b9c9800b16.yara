
rule k2321_1b9054b9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1b9054b9c9800b16"
     cluster="k2321.1b9054b9c9800b16"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['a80b14d228eb7ce1125b67532d074d15','c3d9682f4f9e693c8d0a1a16e77d0f84','d5dd047eb784672f4d434c494bc376d6']"

   strings:
      $hex_string = { ef72e3841dbffd0eb32edfc9e1eed0381874d0b7a3494d73e248711e7edd294305dc69a220836c47f0e80144596b08eb3cb28236c5f54bae23c94a9242dac79e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
