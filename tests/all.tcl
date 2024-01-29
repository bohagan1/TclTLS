# all.tcl --
#
# This file contains a top-level script to run all of the Tcl
# tests.  Execute it by invoking "source all.test" when running tcltest
# in this directory.
#
# Copyright (c) 1998-2000 by Ajuba Solutions.
# All rights reserved.
#
# RCS: @(#) $Id: all.tcl,v 1.5 2000/08/15 18:45:01 hobbs Exp $

set path [file normalize [file dirname [file join [pwd] [info script]]]]
#set auto_path [linsert $auto_path 0 [file normalize [file join [file dirname [info script]] ..]]]
set auto_path [linsert $auto_path 0 [file dirname $path] [file normalize [pwd]]]

if {[lsearch [namespace children] ::tcltest] == -1} {
    package require tcltest
    namespace import ::tcltest::*
}

# Get common functions
if {[file exists [file join $path common.tcl]]} {
    source -encoding utf-8 [file join $path common.tcl]
}

set ::tcltest::testSingleFile false
set ::tcltest::testsDirectory [file dir [info script]]

# We should ensure that the testsDirectory is absolute.
# This was introduced in Tcl 8.3+'s tcltest, so we need a catch.
catch {::tcltest::normalizePath ::tcltest::testsDirectory}

#
# Run all tests in current and any sub directories with an all.tcl file.
#
set ::exitCode 0
if {[package vsatisfies [package require tcltest] 2.5-]} {
    if {[::tcltest::runAllTests] == 1} {
	set ::exitCode 1
    }

} else {
    # Hook to determine if any of the tests failed. Then we can exit with the
    # proper exit code: 0=all passed, 1=one or more failed
    proc tcltest::cleanupTestsHook {} {
	variable numTests
	set ::exitCode [expr {$numTests(Total) == 0 || $numTests(Failed) > 0}]
    }
    ::tcltest::runAllTests
}

#  Exit code: 0=all passed, 1=one or more failed
exit $::exitCode
