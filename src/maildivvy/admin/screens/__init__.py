"""The screens: one module per section, each registering its own routes.

⚠️ **Nothing is imported here.** `app.create_app` imports each screen module and calls
its `register(app)` after the shell exists. Importing them from this file would make
`maildivvy.admin.app` import `maildivvy.admin.screens.domains` import
`maildivvy.admin.app` while the first is still half-built.

Every screen renders through `app.render`, which is the one place the shell, the
sidebar and the "what was just done" sentence are made. Every POST
route is the action of a form on some GET screen of this package, which a
test reads back off the URL map.
"""
