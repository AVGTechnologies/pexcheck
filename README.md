# pexcheck

Pexcheck is a command-line tool for checking the binary compatibilty of public interfaces.

Get the [latest release][1].

  [1]: https://github.com/AVGTechnologies/pexcheck/releases/latest

## Getting started

Consider the following code snippet.
The function `get_minion_stats` is exported from a shared library.

    // in minion.h
    struct minion_stats {
        int attack;
        int health;
    };

    // exported from minions.dll
    minion_stats get_minion_stats(int minion_id);

Here, the function `get_minion_stats` and the structure `minion_stats` and form a *public interface*.
Other libraries and executables directly use these entities and depend on their binary stability.
Changes to the public interface (to the parameters or the return type of the function
or the names or types of the struct members) will likely cause clients to malfunction.
Such errors are usually not caught at compile time
and are difficult to isolate when they surface as bugs during runtime.

Pexcheck provides means to construct an accurate description of the public interface.
By storing the description of a released library and comparing it to the new description
during build, changes can be caught early.

Simply run pexcheck with the name of the shared library as a parameter
and the description of the public interface will be printed to the standard output.

    > pexcheck minions.dll
    %exported_functions

    fn get_minion_stats minion_stats(int)
    type minion_stats 0:var:attack:int 4:var:health:int

The output is divided into a header and a body, separated by a blank line.
The header specifies the set of functions and types that are considered
a public interface.
By default, the public interface is assumed to consist of exactly
all exported functions and entities these functions transitively reference.

Each line in the body describes a structure of one public entity
or an entity that is transitively referenced from one.
In this case the function `get_minion_stats` is part of the public interface,
because it is an exported function and `%exported_functions` directive
appears in the header.
The function references the structure `minion_stats`, which is therefore included
in the body too.
The lines are sorted alphabetically.

You can ask pexcheck to output the description to a separate file.

    > pexcheck minions.dll -o minions.pex

It is recommended that you commit the .pex file along with your source files
so that it can be used as a template.
During build, you run pexcheck on the newly built file and compare the output
against the template.

Let's say, that someone modifies the minion_stats struction as follows.

    // in a modified minion.h
    struct minion_stats {
        int mana_cost;    // breaks binary compatibility
        int attack;
        int health;
    };

Such change breaks binary compatibility,
since code that is compiled against the old version of `minion.h`
will continue to access `attack` member at offset 0, even though it was moved to offset 4.

Running pexcheck will produce the following output.

    > pexcheck.exe quick_dll.dll
    %exported_functions

    fn get_minion_stats minion_stats(int)
    type minion_stats 0:var:mana_cost:int 4:var:attack:int 8:var:health:int

Notice the changes in last line of the description.
You can compare the output to the pex template yourself,
or you can use pexcheck to perform the comparison.

    > pexcheck minions.dll -c minions.pex
    quick_dll.pex(1): error: cross-module compatibility check failed
    -type minion_stats 0:var:attack:int 4:var:health:int
    +type minion_stats 0:var:mana_cost:int 4:var:attack:int 8:var:health:int

If you use the `-c` parameter, pexcheck will return with a nonzero exit code
if the comparison fails, simplifying its use as part of a build system.
