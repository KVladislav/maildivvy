"""Install step 9's pure parts: what `postconf` has to be told, and the
five lookup maps the product writes.

Postfix itself - the listeners, the maps against the real database, a submission that
reaches the stub relay with its own credential - is proved on the test VM.
"""

import re
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from maildivvy_postconf import actions, normalise, parse_main, parse_master, parse_overrides

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "postfix"
SCHEMA = ROOT / "schema" / "0001_initial.sql"
CERT_NAME = "mail.example.test"


def variables(**changes):
    """The role's own variables, with the settings a run supplies."""
    values = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    values.update(yaml.safe_load((ROLE / "vars" / "main.yml").read_text()))
    values["maildivvy_cert_name"] = CERT_NAME
    values["maildivvy_cert_mode"] = "acme"
    values.update(changes)
    # the role's vars refer to one another; Ansible resolves that lazily, we here
    env = Environment(undefined=StrictUndefined)
    for _ in range(4):
        values = yaml.safe_load(env.from_string(yaml.safe_dump(values)).render(values))
    return values


def render(name, **context):
    env = Environment(loader=FileSystemLoader(str(ROLE / "templates")), undefined=StrictUndefined,
                      keep_trailing_newline=True)
    return env.get_template(name).render({**variables(), **context})


def tasks():
    return yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())


def task_text():
    return (ROLE / "tasks" / "main.yml").read_text()


def task_names():
    return [task.get("name", "") for task in tasks()]


def main_cf():
    return variables()["maildivvy_postfix_main"]


def service(key):
    return variables()["maildivvy_postfix_services"][key]


def maps():
    return variables()["maildivvy_postfix_maps"]


def map_file(entry):
    return render("map.cf.j2", item=entry)


# --- the module that tells postconf what to change ---------------------------------

def test_a_continued_main_cf_value_reads_as_one_value():
    text = ("myhostname = mail.example.test\n"
            "smtpd_sender_restrictions = reject_sender_login_mismatch,\n"
            "    permit_sasl_authenticated,\n"
            "\treject\n"
            "mydestination =\n"
            "# a comment\n")
    assert parse_main(text) == {
        "myhostname": "mail.example.test",
        "smtpd_sender_restrictions": "reject_sender_login_mismatch, permit_sasl_authenticated, reject",
        "mydestination": "",
    }


def test_a_services_own_arguments_are_kept_and_its_overrides_are_not_part_of_it():
    # `postconf -M` prints a service's `-o` overrides after its command, on the one line
    text = ("smtp       inet  n       -       n       -       -       smtpd\n"
            "relay      unix  -       -       n       -       -       smtp -o syslog_name=postfix/relay\n"
            "submissions inet n - y - - smtpd -o smtpd_tls_wrappermode=yes -o smtpd_sasl_type=dovecot\n")
    assert parse_master(text) == {
        "smtp/inet": "smtp inet n - n - - smtpd",
        "relay/unix": "relay unix - - n - - smtp",
        "submissions/inet": "submissions inet n - y - - smtpd",
    }


def test_the_overrides_are_read_back_per_service_and_parameter():
    text = ("submissions/inet/smtpd_sasl_path = private/auth\n"
            "127.0.0.1:smtp/inet/smtpd_client_restrictions = permit_mynetworks,reject\n")
    assert parse_overrides(text) == {
        "submissions/inet": {"smtpd_sasl_path": "private/auth"},
        "127.0.0.1:smtp/inet": {"smtpd_client_restrictions": "permit_mynetworks,reject"},
    }


def test_nothing_is_written_when_the_machine_already_says_it():
    want = {"main": {"smtputf8_enable": "no"},
            "services": {"submissions/inet": {"definition": "submissions inet n - y - - smtpd",
                                              "overrides": {"smtpd_sasl_type": "dovecot"}}},
            "absent": ["smtp/inet"]}
    have_main = {"smtputf8_enable": "no", "myhostname": "kept"}
    have_services = {"submissions/inet": "submissions  inet  n  -  y  -  -  smtpd"}
    have_overrides = {"submissions/inet": {"smtpd_sasl_type": "dovecot"}}
    assert actions(**want, have_main=have_main, have_services=have_services,
                   have_overrides=have_overrides) == []


def test_a_parameter_the_machine_reads_otherwise_is_set_and_the_rest_left_alone():
    todo = actions(main={"default_transport": "error:none", "smtputf8_enable": "no"},
                   services={}, absent=[],
                   have_main={"default_transport": "error", "myhostname": "kept"},
                   have_services={}, have_overrides={})
    assert todo == [("main", "default_transport=error:none"), ("main", "smtputf8_enable=no")]


def test_the_distributions_own_service_is_removed_only_while_it_is_there():
    present = actions(main={}, services={}, absent=["smtp/inet"],
                      have_main={}, have_services={"smtp/inet": "smtp inet n - n - - smtpd"},
                      have_overrides={})
    assert present == [("remove-service", "smtp/inet")]
    assert actions(main={}, services={}, absent=["smtp/inet"], have_main={},
                   have_services={}, have_overrides={}) == []


def test_a_rewritten_service_has_every_override_written_again():
    # ⚠️ measured on 3.10.6: `postconf -M '<service>=<definition>'` DROPS the service's
    # own `-o` lines, so a definition that changed takes all of them with it
    todo = actions(main={},
                   services={"submissions/inet": {
                       "definition": "submissions inet n - y - - smtpd",
                       "overrides": {"smtpd_sasl_type": "dovecot", "smtpd_tls_wrappermode": "yes"}}},
                   absent=[], have_main={},
                   have_services={"submissions/inet": "submissions inet n - n - - smtpd"},
                   have_overrides={"submissions/inet": {"smtpd_sasl_type": "dovecot",
                                                        "smtpd_tls_wrappermode": "yes"}})
    assert todo == [("service", "submissions/inet=submissions inet n - y - - smtpd"),
                    ("override", "submissions/inet/smtpd_sasl_type=dovecot"),
                    ("override", "submissions/inet/smtpd_tls_wrappermode=yes")]
    assert todo.index(("service", "submissions/inet=submissions inet n - y - - smtpd")) == 0


def test_an_override_nobody_asked_for_is_taken_off_a_service_we_own():
    todo = actions(main={},
                   services={"submissions/inet": {"definition": "submissions inet n - y - - smtpd",
                                                  "overrides": {"smtpd_sasl_type": "dovecot"}}},
                   absent=[], have_main={},
                   have_services={"submissions/inet": "submissions inet n - y - - smtpd"},
                   have_overrides={"submissions/inet": {"smtpd_sasl_type": "dovecot",
                                                        "smtpd_tls_security_level": "may"}})
    assert todo == [("remove-override", "submissions/inet/smtpd_tls_security_level")]


def test_a_definition_is_compared_by_its_fields_not_by_its_spacing():
    assert normalise("submissions  inet   n - y  - -  smtpd") == "submissions inet n - y - - smtpd"


# --- main.cf: the boundary -----------------

def test_both_transports_are_error_with_the_text_that_comes_back_in_the_refusal():
    values = main_cf()
    assert values["default_transport"] == values["relay_transport"]
    assert values["default_transport"].startswith("error:")
    assert values["default_transport"] != "error"  # the text is part of the value
    assert "per-sender" in values["default_transport"]
    # a relay host does not override the guard, so none is configured
    assert values["relayhost"] == ""
    assert values["mydestination"] == ""  # the server owns no mail zone


def test_a_sender_gets_a_transport_only_through_the_per_sender_map():
    values = main_cf()
    assert values["sender_dependent_default_transport_maps"].endswith("maildivvy-transport.cf")
    assert values["sender_dependent_relayhost_maps"].endswith("maildivvy-relayhost.cf")
    assert all(values[name].startswith("pgsql:/etc/postfix/")
               for name in ("sender_dependent_default_transport_maps", "sender_dependent_relayhost_maps"))
    assert "transport_maps" not in values  # nothing keyed by recipient


def test_the_relay_credential_is_chosen_by_sender_and_the_relay_is_authenticated_over_tls():
    values = main_cf()
    assert values["smtp_sender_dependent_authentication"] == "yes"
    assert values["smtp_sasl_auth_enable"] == "yes"
    assert values["smtp_sasl_security_options"] == "noanonymous"
    assert values["smtp_sasl_password_maps"].endswith("maildivvy-sasl-password.cf")


def test_the_providers_certificate_is_verified_by_its_configured_name_against_the_bundle():
    """`encrypt` took any certificate, and the password went to whoever presented one."""
    values = main_cf()
    assert values["smtp_tls_security_level"] == "secure"
    assert values["smtp_tls_secure_cert_match"] == "nexthop"
    # a FILE, read before the chrooted client starts; a CA directory would be looked up
    # inside the chroot, where it is not
    assert values["smtp_tls_CAfile"] == "/etc/ssl/certs/ca-certificates.crt"
    assert "smtp_tls_CApath" not in values


def test_a_provider_on_465_has_a_client_of_its_own_in_wrapper_mode():
    """The plain client waited for a clear-text greeting from a provider's 465."""
    entry = service("smtps/unix")
    assert normalise(entry["definition"]) == "smtps unix - - y - - smtp"
    assert entry["overrides"] == {"smtp_tls_wrappermode": "yes"}
    view = SCHEMA.read_text().split("CREATE VIEW postfix_transport AS", 1)[1].split(";", 1)[0]
    assert "CASE WHEN e.smtp_port = 465 THEN 'smtps' ELSE 'smtp' END" in view


def test_the_sender_is_rewritten_in_the_smtp_client_and_never_in_cleanup():
    values = main_cf()
    assert values["smtp_generic_maps"].endswith("maildivvy-generic.cf")
    for canonical in ("canonical_maps", "sender_canonical_maps", "recipient_canonical_maps"):
        assert canonical not in values, f"{canonical} would rewrite before the per-sender lookups"


def test_smtputf8_is_off_and_only_the_family_served_is_configured():
    values = main_cf()
    assert values["smtputf8_enable"] == "no"
    assert values["inet_protocols"] == "ipv4"
    assert values["inet_interfaces"] == "all"  # 465 is served off the loopback; 25 is pinned in master.cf


def test_465_is_given_the_products_certificate_and_not_the_distributions_snakeoil():
    values = main_cf()
    assert values["smtpd_tls_cert_file"] == f"/etc/ssl/certs/{CERT_NAME}.crt"
    assert values["smtpd_tls_key_file"] == f"/etc/ssl/private/{CERT_NAME}.key"
    assert "snakeoil" not in yaml.safe_dump(values)
    assert values["smtpd_tls_protocols"] == ">=TLSv1.2"
    assert values["smtpd_tls_mandatory_protocols"] == ">=TLSv1.2"


def test_this_step_binds_no_milter_at_all():
    # ⛔ install step 14's, after the daemon is proved running: a socket nothing listens
    # on, named here, would tempfail every submission for five steps
    values = variables()
    assert not any(name.startswith("milter") or name == "smtpd_milters" for name in main_cf())
    assert not any(name.startswith("milter") or name == "smtpd_milters"
                   for entry in values["maildivvy_postfix_services"].values()
                   for name in (entry.get("overrides") or {}))


def test_the_binding_step_14_writes_is_named_as_another_steps_and_left_alone():
    # ⛔ this step writes no binding, and a re-run of it must not TAKE AWAY the one step
    # 14 wrote either: the two together would unbind a proved milter on every run
    assert service("submissions/inet")["keep"] == ["smtpd_milters"]
    have = {"submissions/inet": {"smtpd_milters": "unix:maildivvy/milter.sock",
                                 "syslog_name": "postfix/submissions"}}
    wanted = {"submissions/inet": {"definition": "submissions inet n - y - - smtpd",
                                   "keep": ["smtpd_milters"],
                                   "overrides": {"syslog_name": "postfix/submissions"}}}
    machine = {"submissions/inet": "submissions inet n - y - - smtpd"}
    assert actions({}, wanted, [], {}, machine, have) == []
    # the control: without `keep` the same reading takes the binding away
    del wanted["submissions/inet"]["keep"]
    assert actions({}, wanted, [], {}, machine, have) == [
        ("remove-override", "submissions/inet/smtpd_milters")]


def test_a_definition_that_has_to_be_rewritten_puts_a_kept_override_back():
    # ⚠️ measured on 3.10.6: `postconf -M '<service>=…'` drops that service's own `-o`
    # lines, and a binding another step owns would go with them
    have = {"submissions/inet": {"smtpd_milters": "unix:maildivvy/milter.sock"}}
    wanted = {"submissions/inet": {"definition": "submissions inet n - y - - smtpd",
                                   "keep": ["smtpd_milters"], "overrides": {}}}
    assert actions({}, wanted, [], {}, {"submissions/inet": "submissions inet n - n - - smtpd"},
                   have) == [("service", "submissions/inet=submissions inet n - y - - smtpd"),
                             ("override", "submissions/inet/smtpd_milters=unix:maildivvy/milter.sock")]


# --- master.cf: the two listeners -------------------------------

def test_submission_is_465_in_wrapper_mode_with_dovecots_socket_and_nothing_else():
    entry = service("submissions/inet")
    assert normalise(entry["definition"]) == "submissions inet n - y - - smtpd"
    overrides = entry["overrides"]
    assert overrides["smtpd_tls_wrappermode"] == "yes"
    assert overrides["smtpd_tls_security_level"] == "encrypt"
    assert overrides["smtpd_sasl_type"] == "dovecot"
    assert overrides["smtpd_sasl_auth_enable"] == "yes"
    assert overrides["smtpd_tls_auth_only"] == "yes"
    assert overrides["smtpd_client_restrictions"] == "permit_sasl_authenticated,reject"
    assert overrides["smtpd_recipient_restrictions"] == "permit_sasl_authenticated,reject"


def test_587_is_never_a_service():
    text = yaml.safe_dump(variables()["maildivvy_postfix_services"])
    assert "submission/" not in text and "587" not in text


def test_the_login_mismatch_check_is_followed_by_an_explicit_permit_before_the_reject():
    # reject_sender_login_mismatch answers DUNNO on a match, so a bare reject after it
    # refuses the very messages it just approved
    restrictions = service("submissions/inet")["overrides"]["smtpd_sender_restrictions"].split(",")
    assert restrictions == ["reject_sender_login_mismatch", "permit_sasl_authenticated", "reject"]


def test_every_path_the_chrooted_server_uses_is_relative_to_the_queue_directory():
    entry = service("submissions/inet")
    assert entry["definition"].split()[4] == "y"  # the chroot column
    assert entry["overrides"]["smtpd_sasl_path"] == "private/auth"
    assert not entry["overrides"]["smtpd_sasl_path"].startswith("/")


def test_no_listener_but_465_and_sendmail_for_root_alone():
    """The loopback 25 and `sendmail` let any local process send as any mailbox."""
    values = variables()
    assert values["maildivvy_postfix_absent"] == ["smtp/inet", "127.0.0.1:smtp/inet"]
    listeners = [key for key in values["maildivvy_postfix_services"] if key.endswith("/inet")]
    assert listeners == ["submissions/inet"]
    assert main_cf()["authorized_submit_users"] == "root"


# --- the five lookup maps --------------------------------

def test_the_five_maps_are_the_five_views_the_schema_grants_postfix():
    granted = re.search(r"GRANT SELECT ON ([^;]+) TO maildivvy_postfix;", SCHEMA.read_text(), re.S)
    views = {name.strip() for name in granted.group(1).replace("\n", " ").split(",")}
    assert {entry["view"] for entry in maps()} == views
    assert len(maps()) == 5


def test_a_map_names_a_passfile_and_carries_no_password():
    text = map_file(maps()[0])
    assert "postgresql://maildivvy_postfix@127.0.0.1/maildivvy?passfile=/etc/postfix/maildivvy.pgpass" in text
    directives = [line.split("=")[0].strip() for line in text.splitlines()
                  if line and not line.startswith("#")]
    assert directives == ["hosts", "dbname", "query"]  # no `password`, and no `user` to key one by


def test_every_lookup_key_in_a_query_is_quoted():
    for entry in maps():
        text = map_file(entry)
        query = next(line for line in text.splitlines() if line.startswith("query ="))
        assert f"FROM {entry['view']} WHERE mkey = '%s'" in query
        assert not re.search(r"(?<!')%s(?!')", query), query


def test_each_map_reads_one_view_and_answers_one_column():
    names = {entry["name"] for entry in maps()}
    assert names == {"sender-login", "sasl-password", "generic", "transport", "relayhost"}
    for entry in maps():
        assert "SELECT mvalue" in map_file(entry)


# --- the step's own order -----------------------------------------------

def test_nothing_is_appended_to_a_postfix_file_and_no_include_directory_is_written():
    # the comments say `main.cf.d` is not a directory Postfix reads; the tasks may not
    text = "\n".join(line for line in task_text().splitlines() if not line.lstrip().startswith("#"))
    assert ">>" not in text and "main.cf.d" not in text and "master.cf.d" not in text
    assert "maildivvy_postconf" in text  # postconf edits the named settings, nothing else


def test_postfix_check_runs_before_every_restart():
    names = task_names()
    check = next(i for i, name in enumerate(names) if "postfix check" in name)
    restart = next(i for i, name in enumerate(names) if "restart" in name.lower())
    assert check < restart, names


def test_the_account_joins_ssl_cert_and_the_deploy_hook_is_run_again_after_it():
    names = task_names()
    group = next(i for i, name in enumerate(names) if "ssl-cert" in name)
    hook = next(i for i, name in enumerate(names) if "deploy hook" in name)
    assert group < hook, names
    # the hook is lego's and refuses in self-signed mode, where nothing was issued
    assert tasks()[hook]["when"] == "maildivvy_cert_mode != 'self-signed'"
