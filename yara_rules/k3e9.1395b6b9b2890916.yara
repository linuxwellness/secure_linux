
rule k3e9_1395b6b9b2890916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395b6b9b2890916"
     cluster="k3e9.1395b6b9b2890916"
     cluster_size="19"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ipamor backdoor xyzbaukwkdpb"
     md5_hashes="['19f80040a2e976278fa10882bbe8223f','3963b5f791c7e15ddbb8233e4f923122','f81a0bdfbbc1e6430ba5982e2c48a81a']"

   strings:
      $hex_string = { 10c1f8782750fea088c2126d7cf134606a1b6485ea3b556c3704110e940b809b6884aa1730b9d8c328d439f09c5f9a1592fb9f4ac97ec605221ffa573341d663 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
