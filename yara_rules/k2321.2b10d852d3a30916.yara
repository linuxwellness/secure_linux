
rule k2321_2b10d852d3a30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b10d852d3a30916"
     cluster="k2321.2b10d852d3a30916"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['05831b6e89319742e4c5ba019bbe0c1e','1e4ceda1400ddb2d15ddee4ad3ebdf4a','9ee002eda01e16abfcbe85b4a6bdde4f']"

   strings:
      $hex_string = { 0d7fe86bac6f967aa7102f6ad5793b25d4b1e5a1789fe0eb46ffb39e657d076888dc09170a8b26fdebb99458fa3e9adb6987a85d3dfc768d9cbb40f7babd9734 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
