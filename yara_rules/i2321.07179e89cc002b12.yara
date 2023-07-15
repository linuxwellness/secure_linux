
rule i2321_07179e89cc002b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.07179e89cc002b12"
     cluster="i2321.07179e89cc002b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['6a8b04d237e96a577a0dfd46657780b1','8f75607edb4b7c6117c18ecb36807033','ef9920e288f0e48d6ef9cb3e3f55556a']"

   strings:
      $hex_string = { 576f9e2985a9c9d1898d78bd7ba2f2c2f862a571b158ae2d56462fc49ecb69ec9938bbe3958b69e0f048314e70a3c55a9c711cebe87c6db6d24817125b4c1e1b }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
