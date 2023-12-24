#
# Test Vectors
#

#
# Create test case and output to test file
#
proc do_test {group tail file_num tc digest params} {
    array set config [list Msg "" Repeat 1]
    array set config $params

    # Test info
    set line [format "tcltest::test %s-%d.%d {%s}" $group $file_num $tc $tail]
    append line " \\\n\t"

    # Test constraints
    append line [format "-constraints %s" [string map [list "-" "_"] $digest]]
    append line " \\\n\t"

    # Test setup
    set is_hex [expr {[string index $config(Msg) 0] ne "\""}]
    if {[info exists config(Len)] && $config(Len) == 0} {
	set data {""}
	set is_hex 0
    } else {
	set data $config(Msg)
    }
    if {$config(Repeat) > 1} {
	set data [format {[string repeat %s %d]} $data $config(Repeat)]
    }

    if {$is_hex} {
	append line [format {-setup {set data [binary decode hex %s]}} $data]
    } else {
	append line [format {-setup {set data %s}} $data]
    }
    append line " \\\n\t"

    # Test body
    append line [format {-body {tls::digest -digest %s -data $data}} $digest]
    append line " \\\n\t"

    # Test cleanup

    # Test result
    set result ""
    foreach key [list MD Mac Output] {
	if {[info exists config($key)]} {
# For SHAKE XOF, need to truncate to config(Len) size/8 (bits -> bytes)
	    set result $config($key)
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
    set digest [string map [list LongMsg "" ShortMsg "" Monte "" "_" "-"] $tail]
    set params [list]

    # Add config info
    puts $out [format "# Auto generated from \"%s\"" [file tail $filename]]
    puts $out "package require tls"
    puts $out "package require tcltest\n"
    puts $out [format "tcltest::testConstraint %s %s" [string map [list "-" "_"] $digest] \
	[format {[expr {[lsearch -nocase [tls::digests] %s] > -1}]} $digest]]
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
		puts $out [do_test $group $tail $file_num [incr tc] $digest $params]
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
	puts $out [do_test $group $tail $file_num [incr tc] $digest $params]
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
