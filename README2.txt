This repository branch is set up for the Pocket Privacy Scope project.
We are implementing taint tracking into the virtual machine interpreter.

Rules:

- Taint tracking features should only be enabled when CFLAGS contains
  the -DWITH_TAINT_TRACKING compile flag. This flag should be added to
  either Android.mk or vm/Android.mk depending on where code changes are
  required.

  Subsequently, code should be conditionally included with the C
  preprocessor via "#ifdef WITH_TAINT_TRACKING" conditionals.

Setup Instructions:

- Checkout the Android 1.5r2 source code:

  % mkdir tdroid ; cd tdroid
  % repo init -u git://android.git.kernel.org/platform/manifest.git \
              -b android-1.5r2

- Create the custom local_manifest.xml

  % vim .repo/local_manifest.xml

----------------------------------------------------------------------
<manifest>
  <remote  name="siis"
           fetch="ssh://git@siisgit.cse.psu.edu/" />
  <remove-project name="platform/dalvik"/>
  <project path="dalvik" remote="siis" 
     name="android/platform/dalvik" revision="taint" />
</manifest>
----------------------------------------------------------------------

- Pull in the new repo:

 % repo sync

- Create our working branch for "master" development pushes

 % cd dalvik
 % git branch --track taint siis/taint
 % git checkout taint

- The "taint" branch should always compile. Create your own topic
  branch for your changes before merging them with the main "taint"
  branch.

For project details or setup instructions, contact:

  William Enck <enck@cse.psu.edu>

