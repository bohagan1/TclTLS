#
# Test Vectors
#

#
# Create test case and output to test file
#
proc do_test {group tail file_num tc mac digest cipher params} {
    array set config $params

    # Test info
    set line [format "tcltest::test %s-%d.%d {%s}" $group $file_num $tc $tail]
    append line " \\\n\t"

    # Test constraints - Remove dashes since tcltest doesn't like them
    append line [format "-constraints {%s %s %s}" [string map [list "-" "_"] $mac] \
	[string map [list "-" "_"] $digest] [string map [list "-" "_"] $cipher]]
    append line " \\\n\t"

    # Test setup
    append line "-setup {} \\\n\t"

    # Test body parameters
    set cmd [format "tls::%s -hex" [string tolower $mac]]
    if {$digest ne ""} {
	append cmd " -digest " $digest
    }
    if {$cipher != ""} {
	append cmd " -cipher " $cipher
    }
    foreach {param names type} [list -key [list Key key] s -data [list Msg] s] {
	foreach name $names {
	    if {[info exists config($name)]} {
		set data $config($name)
		# Handle hex string
		if {$type eq "s" && [string length $data] > 0 && [string index $data 0] ne "\""} {
		    set data [format {[binary decode hex %s]} $data]
		}
		if {[string length $data] > 0} {
		    append cmd " " $param " " $data
		}
	    }
	}
    }

    # Test result
    set result ""
    foreach name [list Trunc Mac Output] {
	if {[info exists config($name)]} {
	    set result $config($name)
	    break
	}
    }
    set result_len 0
    if {[info exists config(Tlen)] && $config(Tlen) != ""} {
	set result_len $config(Tlen)
	set end $result_len
    }
    if {[string index $result 0] ne "\""} {
	set result_len [expr {$result_len * 2}]
	set end [expr {$result_len - 1}]
    }

    # Test body
    if {$result_len > 0} {
	append line "-body \{string range \[" $cmd [format "\] 0 %d\} \\\n\t" $end]
    } else {
	append line "-body \{" $cmd "\} \\\n\t"
    }

    # Test cleanup
    #append line "-cleanup {} \\n\t"
    
    append line [format {-match exact -result %s} $result]

    # Return codes
    #append line { -returnCodes 0}
    return $line
}

#
# Parse test vector file and get test cases config info
#
proc parse {group filename file_num} {
    set tc 0
    set digest ""
    set cipher ""
    set mac ""

    # Open input file
    if {[catch {open $filename r} ch]} {
	return -code error $ch
    }
    set tail [file rootname [file tail $filename]]

    # Open output file
    if {[catch {open [format "%s.test" [file rootname $filename]] w} out]} {
	return -code error $ch
    }

    # Get mac and digest
    set index [string first "-" [string map [list "_" "-"] $tail]]
    if {$index > -1} {
	set mac [string range $tail 0 [expr {$index - 1}]]
	if {[string match -nocase "CMAC" $mac]} {
	    set cipher [string range $tail [incr index] end]
	} else {
	    set digest [string range $tail [incr index] end]
	}
    } else {
	set mac $tail
	set digest ""
	set cipher ""
    }
    set params [list]

    # Add config info
    puts $out [format "# Auto generated from \"%s\"" [file tail $filename]]
    puts $out [format "lappend auto_path %s" {[file dirname [file dirname [file dirname [file dirname [file join [pwd] [info script]]]]]]}]
    puts $out "package require tls"
    puts $out "package require tcltest\n"
    puts $out [format "tcltest::testConstraint %s %s" $mac \
	[format {[expr {[lsearch -nocase [tls::macs] %s] > -1}]} [string map [list "-" "_"] $mac]]]
    if {[string match -nocase "CMAC" $mac] && $cipher ne ""} {
	puts $out [format "tcltest::testConstraint %s %s" [string map [list "-" "_"] $cipher] \
	    [format {[expr {[lsearch -nocase [tls::ciphers] %s] > -1}]} $cipher]]
    } elseif {[string match -nocase "HMAC" $mac] && $digest ne ""} {
	puts $out [format "tcltest::testConstraint %s %s" [string map [list "-" "_"] $digest] \
	    [format {[expr {[lsearch -nocase [tls::digests] %s] > -1}]} $digest]]
    }
    puts $out "catch {tls::provider legacy}"
    puts $out ""

    # Process file
    while {![eof $ch]} {
	gets $ch line
	set line [string trim $line]
	set len [string length $line]

	if {[string index $line 0] in [list "#"]} {
	    # Skip comments and info lines
	    continue

	} elseif {[string index $line 0] eq "\["} {
	    # Digest size
	    if {[scan $line {[L=%d]} size] > 0} {
		array set sizes [list 20 SHA1 28 SHA224 32 SHA256 48 SHA384 64 SHA512]
		if {[info exists sizes($size)]} {
		    set digest $sizes($size)
		    puts $out [format "tcltest::testConstraint %s %s" $digest \
			[format {[expr {[lsearch -nocase [tls::digests] %s] > -1}]} [string map [list "-" "_"] $digest]]]
		}
	    }

	} elseif {$len == 0} {
	    if {[llength $params] > 0} {
		# Do test if end of params
		puts $out [do_test $group $tail $file_num [incr tc] $mac $digest $cipher $params]
		puts $out ""
		set params [list]
	    } else {
		# Empty line
	    }

	} else {
	    # Append args to params
	    set index [string first "=" $line]
	    if {$index > -1} {
		set key [string trim [string range $line 0 [expr {$index - 1}]]]
		set value [string trim [string range $line [expr {$index + 1}] end]]
		lappend params $key $value
	    }
	}
    }

    # Handle last test case
    if {[llength $params] > 0} {
	puts $out [do_test $group $tail $file_num [incr tc] $mac $digest $cipher $params]
	puts $out ""
    }
    
    # Cleanup
    puts $out "# Cleanup\n::tcltest::cleanupTests\nreturn"
    close $ch
    close $out
}

#
# Read all config files in directory
#
proc main {path} {
    set file_num 0
    set group [file rootname [file tail $path]]

    foreach filename [glob -directory $path *.txt *.rsp] {
	puts [format "Processing %s" $filename]
	set tail [file tail $filename]
	if {[string match -nocase "Readme.txt" $tail] || [string match -nocase "*Monte.txt" $tail]} {
	    continue
	}

	set tail [file rootname [file tail $filename]]
	set digest [string map [list LongMsg "" ShortMsg "" Monte "" "_" "-"] $tail]
	set id [format "%s_%s" $group $digest]
	set test_num [incr test_ids($id)]
	parse $id $filename $test_num
    }
}

main [pwd]
exit
