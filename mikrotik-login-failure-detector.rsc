# Script for blacklisting failed login attempts on MikroTik routers
# This script monitors failed login attempts and automatically adds IP addresses
# to a blacklist based on configurable thresholds.

# Configuration Variables
:local logEnabled true   ;# Set to true for logging, false to disable logging
:local timeWindow 20m    ;# Time window to monitor login attempts
:local warnThreshold 3   ;# Number of failed attempts before blacklisting an IP
:local addressListName "blacklist"   ;# Name of the firewall address list to use for blacklisting
:local blacklistTimeout "10m"   ;# Timeout duration for blacklisted IPs

# Function to log messages, only if logging is enabled
:if ($logEnabled) do={
    :log info "Login Failure Detector script started."
}

# Retrieve relevant log entries based on time
:local logEntries [:toarray [/log find where (topics~"system" && topics~"error" && message~"login failure" && (([:timestamp]+([/system clock get gmt-offset]."s"))-[:totime (time)]) <= $timeWindow )]]

# Initialize data structures
:local ipList []   ;# List to store IP addresses
:local ipCountList []   ;# List to store the count of failed attempts for each IP
:local addedToBlacklist ""   ;# String to hold IPs added to the blacklist
:local failedAttemptsMessage ""   ;# Message to store the list of failed attempts
:local blacklistMessage ""   ;# Message to store the list of IPs added to the blacklist
:local addedAnyToBlacklist false   ;# Flag to indicate if any IPs were added to the blacklist
:local newlyAddedList []   ;# Array to store new IPs added to the blacklist

# Loop through all log entries
:foreach logId in=$logEntries do={

    :local logMessage [/log get $logId message]

    # Extract IP address from the log message (after "from ")
    :local address [:pick $logMessage ([:find $logMessage "from "] + 5) [:find $logMessage " via"]]

    # If the address contains ":", but not ".", it's a MAC address, so we skip it
    :if (([:find $address ":"] > 0) && ([:find $address "."] = nil)) do={
        :log info ("MAC address detected: " . $address . ", skipping.")
    } else={

        # Check if the IP is already in the list
        :local foundIndex -1
        :for i from=0 to=([:len $ipList] - 1) do={
            :if ([:pick $ipList $i] = $address) do={
                :set foundIndex $i
            }
        }

        # If the IP exists, increment its count
        :if ($foundIndex != -1) do={
            :set ($ipCountList->$foundIndex) (($ipCountList->$foundIndex) + 1)
        } else={
            # Otherwise, add the IP to the list
            :set ipList ($ipList, $address)
            :set ipCountList ($ipCountList, 1)
        }
    }
}

# Create the message for failed login attempts
:set failedAttemptsMessage ("Failed attempts: " . [ :len $ipList ])
:set blacklistMessage "List of IPs added to blacklist: "

# Output and possibly add to blacklist
:for i from=0 to=([:len $ipList] - 1) do={
    :local ip [:pick $ipList $i]
    :local count [:pick $ipCountList $i]
    :if ($count >= $warnThreshold) do={

        :set addedAnyToBlacklist true
        :set addedToBlacklist ($addedToBlacklist . $ip . " (" . $count . "), ")

        # Add IP to the address list if it's not already there
        :if ([:len [/ip firewall address-list find where list=$addressListName and address=$ip]] = 0) do={
            /ip firewall address-list add list=$addressListName address=$ip timeout=$blacklistTimeout comment="Auto blacklist from login failures"
            :set newlyAddedList ($newlyAddedList, $ip)  ;# Record the newly added IP
        }
    }
}

# Create a list of IPs that attempted to log in
:local ipListStr ""
:for i from=0 to=([:len $ipList] - 1) do={
    :local ip [:pick $ipList $i]
    :set ipListStr ($ipListStr . $ip . ", ")
}

######################
# Output to log
######################

# Extract hours, minutes, and seconds from the time window
:local hours [:tonum [:pick $timeWindow 0 2]]
:local minutes [:tonum [:pick $timeWindow 3 5]]
:local seconds [:tonum [:pick $timeWindow 6 8]]

# Convert to total seconds
:local totalSeconds ($hours * 3600 + $minutes * 60 + $seconds)

:if ([ :len $ipList] = 0) do={
    :log info ("Login monitor: No failed login attempts in the last " . $totalSeconds . " sec")
} else={

    :local failedAttemptsMessage ("Failed attempts in the last " . $totalSeconds . " sec: ")
    :local newBlacklistEntries ""  ;# For holding newly added IPs

    # Generate output of IP addresses and labels
    :for i from=0 to=([:len $ipList] - 1) do={
        :local ip [:pick $ipList $i]
        :local count [:pick $ipCountList $i]
        :local label ""

        :if ($count >= $warnThreshold) do={

            # Check if the IP is newly added
            :local isNew false
            :for j from=0 to=([:len $newlyAddedList] - 1) do={
                :if ([:pick $newlyAddedList $j] = $ip) do={
                    :set isNew true
                }
            }

            :if ($isNew) do={
                :set label " [NEW]"
                :set newBlacklistEntries ($newBlacklistEntries . $ip . " (" . $count . "), ")
            } else={
                :set label " [EXISTING]"
            }
        }

        :set failedAttemptsMessage ($failedAttemptsMessage . $ip . " (" . $count . ")" . $label . " ")
    }

    :log warning ("Login monitor: " . $failedAttemptsMessage)

    :if ([:len $newBlacklistEntries] > 0) do={
        :log error ("Login monitor: IP addresses added to blacklist: " . [:pick $newBlacklistEntries 0 ([:len $newBlacklistEntries] - 2)])
    }
}
