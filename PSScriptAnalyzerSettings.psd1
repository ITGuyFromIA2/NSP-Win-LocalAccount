@{
 IncludeDefaultRules=$true
 Severity=@('Error','Warning')
 ExcludeRules=@(
  # This module includes an interactive operator menu and standalone test progress.
  'PSAvoidUsingWriteHost'
  # Rights is an intentional collection, consistent with the other NSP Windows helpers.
  'PSUseSingularNouns'
 )
}
