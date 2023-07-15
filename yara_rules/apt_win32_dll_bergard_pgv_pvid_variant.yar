rule apt_win32_dll_bergard_pgv_pvid_variant

{

               meta:

                               copyright = “Fidelis Cybersecurity”
                               reference = "http://www.threatgeek.com/2016/05/"

                strings:

                                $ = "Accept:"

                                $ = "User-Agent: %s"

                                $ = "Host: %s:%d"

                                $ = "Cache-Control: no-cache"

                                $ = "Connection: Keep-Alive"

                                $ = "Cookie: pgv_pvid="

                                $ = "Content-Type: application/x-octet-stream"

                                $ = "User-Agent: %s"

                                $ = "Host: %s:%d"

                                $ = "Pragma: no-cache"

                                $ = "Connection: Keep-Alive"

                                $ = "HTTP/1.0"

                condition:

                                (uint16(0) == 0x5A4D) and (all of them)

        }