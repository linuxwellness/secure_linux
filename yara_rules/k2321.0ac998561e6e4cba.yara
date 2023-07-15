
rule k2321_0ac998561e6e4cba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ac998561e6e4cba"
     cluster="k2321.0ac998561e6e4cba"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['189564ce19d2d9a09379af9c39b2e201','33b6cab1c36cb3c6fba58264064ee157','d90bd82fed8a33112b685dd3579e70d5']"

   strings:
      $hex_string = { 72c53813972f58a6a34384e7f99def03c6f2c33d8874f454f17950220fdc62452b446e118fde245c08a19827179652852578d22794db149e6829a0ac200d6090 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
