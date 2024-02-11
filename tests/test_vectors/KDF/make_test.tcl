#
# Test Vectors
#

#
# Create test case and output to test file
#
proc do_test {group tail file_num tc kdf digest params} {
    array set config $params

    # Test info
    set line [format "tcltest::test %s-%d.%d {%s}" $group $file_num $tc $tail]
    append line " \\\n\t"

    # Test constraints
    append line [format "-constraints {%s %s}" [string map [list "-" "_"] $kdf] [string map [list "-" "_"] $digest]]
    append line " \\\n\t"

    # Test setup
    append line "-setup {} \\\n\t"

    # Test body parameters
    set cmd [format "tls::%s" [string tolower $kdf]]
    if {$digest ne ""} {
	append cmd " -digest " $digest
    }
    foreach {param names type} [list -key [list IKM Key key] s -info [list I info] s -password [list P] s \
	    -salt [list S salt] s -iterations [list c] i -size [list L dkLen dklen] i \
	    -N [list N] i -r [list r] i -p [list p] i] {
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

    # Test body
    append line "-body \{binary encode hex \[" $cmd "\]\} \\\n\t"

    # Test cleanup
    #append line "-cleanup {} \\n\t"

    # Test result
    set result ""
    foreach name [list OKM DK Output] {
	if {[info exists config($name)]} {
	    set result $config($name)
	    break
	}
    }
    
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

    # Open input file
    if {[catch {open $filename r} ch]} {
	return -code error $ch
    }
    set tail [file rootname [file tail $filename]]

    # Open output file
    if {[catch {open [format "%s.test" [file rootname $filename]] w} out]} {
	return -code error $ch
    }

    # Get digest
    lassign [split [string map [list "_" "-"] $tail] "-"] kdf digest
    set params [list]

    # Add config info
    puts $out [format "# Auto generated from \"%s\"" [file tail $filename]]
    puts $out [format "lappend auto_path %s" {[file dirname [file dirname [file dirname [file dirname [file join [pwd] [info script]]]]]]}]
    puts $out "package require tls"
    puts $out "package require tcltest\n"
    puts $out [format "tcltest::testConstraint %s %s" [string map [list "-" "_"] $kdf] \
	[format {[expr {[lsearch -nocase [tls::kdfs] %s] > -1}]} $kdf]]
    if {$digest ne ""} {
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

	if {[string index $line 0] in [list "#" "\["]} {
	    # Skip comments and info lines
	    continue

	} elseif {$len == 0} {
	    if {[llength $params] > 0} {
		# Do test if end of params
		puts $out [do_test $group $tail $file_num [incr tc] $kdf $digest $params]
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
	puts $out [do_test $group $tail $file_num [incr tc] $kdf $digest $params]
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

    foreach filename [glob -directory $path *.txt *ShortMsg.rsp *LongMsg.rsp] {
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
