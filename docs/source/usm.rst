User-Based Security
===================

.. autoclass:: snmp.security.usm.UsmAdmin

   This class manages user credentials at a global scope. SNMP user credentials
   behave differently than most password-protected systems, in that there is no
   central authority involved. Each SNMP engine manages its own users and
   credentials. While one might expect a network administrator to use the same
   set of user names and credentials across all nodes in a network, it is
   conceivable that some nodes might use one set of credentials, while other
   nodes use an unrelated set of credentials. This creates the possibility of a
   name collision, in which two nodes define users with the same user name but
   different passwords or a different selection of algorithms. To allow for such
   configurations, the :class:`UsmAdmin` identifies each user configuration by a
   unique combination of user name and namespace. This allows you to organize
   sets of related user configurations according to the organization of the
   network.

   When determining how to organize users into namespaces, it is important to
   understand that each SNMP engine belongs to exactly one namespace. A
   namespace may contain any number of engines, and any number of user names,
   and a user name may be present in any number of namespaces. There's nothing
   to stop a zealous developer from defining one namespace for every engine. A
   more practical strategy, however, would be to define one namespace for each
   set of hosts that use identical credentials to each other. The most trivial
   arrangement is to ignore the namespace altogether, which is fine so long as
   no two engines use conflicting credentials with a single user name.

   **TL;DR;** ignore the `namespace` parameter unless you have user name
   collisions (with different passwords and/or algorithms) between two different
   SNMP engines.

   .. automethod:: addUser

      This method stores security information for a user. Despite the large
      number of parameters, its behavior is quite straightforward.

      The only required parameter is the `userName`. Other parameters depend on
      the level of security that the user supports. If the user supports
      authentication, then the `authProtocol` parameter specifies the
      authentication algorithm, in the form of a class implementing
      :class:`snmp.security.usm.AuthProtocol`. The `privProtocol` parameter
      serves the same role for a user that supports privacy, and must be a class
      implementing :class:`snmp.security.usm.PrivProtocol`. The `authSecret` and
      `privSecret` parameters specify the authentication and privacy passwords,
      respectively. Alternatively, if the user has a single password for both
      auth and priv, then the `secret` parameter may be used in lieu of the
      other two.

      Normally, a user will select the highest security level that it's
      configuration supports. If you wish for a user to default to a lower level
      of security, you can provide a value for the `defaultSecurityLevel`
      parameter.

      Normally, the first user added (to a namespace) becomes the "default" user
      (for that namespace). To manually designate a user to be the default (for
      its namespace), give a value of ``True`` for the `default` parameter when
      adding that user.

      Lastly, the `namespace` parameter specifies a namespace for the new user
      configuration. For an explanation of namespaces, see above, under
      :class:`UsmAdmin`.
