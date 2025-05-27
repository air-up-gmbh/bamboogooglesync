import json
import os
import secrets
from datetime import datetime, timedelta, timezone

import boto3
import click
from googleapiclient.errors import HttpError

from .bamboo import BambooSession
from .google import create_directory_service
from .options import *


@click.group()
def cli(*args, **kwargs):
    pass


@cli.command()
@bamboo_subdomain
@bamboo_api_key
@google_admin
@google_credentials
@dry_run
def update(
    bamboo_subdomain,
    bamboo_api_key,
    google_admin,
    google_credentials,
    dry_run,
):
    b = BambooSession(bamboo_subdomain, bamboo_api_key)
    g = create_directory_service(google_admin, google_credentials)

    directory = b.get("/employees/directory")
    for employee in directory.get("employees", []):
        # Get detailed employee information including status
        employee_details = b.get(
            f"/employees/{employee['id']}",
            params={
                "fields": ",".join([
                    "workEmail",
                    "preferredName",
                    "firstName",
                    "lastName",
                    "status",
                    "homeEmail",
                    "jobTitle",
                    "supervisorEmail",
                    "department",
                    "employmentType",
                    "id"
                ])
            },
        )
        
        # Merge the detailed info with directory info
        employee.update(employee_details)
        
        update_kwargs = {
            "userKey": employee["workEmail"],
            "body": {
                "primaryEmail": employee["workEmail"],
                "name": {
                    "givenName": employee["preferredName"] or employee["firstName"],
                    "familyName": employee["lastName"],
                },
                "suspended": employee["status"] != "Active",
                "emails": [
                    {
                        "address": employee["homeEmail"],
                        "type": "home",
                    },
                    {
                        "address": employee["workEmail"],
                        "primary": True,
                    },
                ],
                "relations": [
                    {"value": employee["supervisorEmail"], "type": "manager"}
                ],
                "organizations": [
                    {
                        "title": employee["jobTitle"],
                        "primary": True,
                        "department": employee["department"],
                    }
                ],
                "externalIds": [{"value": employee["id"], "type": "organization"}],
            },
        }
        try:
            if dry_run:
                click.echo({"type": "dry_run_update_user", **update_kwargs})
            else:
                g.users().update(**update_kwargs).execute()
                click.echo({"type": "update_user", **update_kwargs})
        except HttpError as e:
            echo_http_error(e, **update_kwargs)
            continue

@cli.command()
@bamboo_subdomain
@bamboo_api_key
@google_admin
@google_credentials
@click.argument('employee-id')
@dry_run
def update_employee(
    bamboo_subdomain,
    bamboo_api_key,
    google_admin,
    google_credentials,
    employee_id,
    dry_run,
):
    b = BambooSession(bamboo_subdomain, bamboo_api_key)
    g = create_directory_service(google_admin, google_credentials)
    
    employee = b.get(
        f"/employees/{employee_id}",
        params={
            "fields": ",".join(
                [
                    "workEmail",
                    "preferredName",
                    "firstName",
                    "lastName",
                    "status",
                    "homeEmail",
                    "jobTitle",
                    "supervisorEmail",
                    "department",
                    "employmentType",
                    "id"
                ]
            )
        },
    )
    
    update_kwargs = {
        "userKey": employee["workEmail"],
        "body": {
            "primaryEmail": employee["workEmail"],
            "name": {
                "givenName": employee["preferredName"] or employee["firstName"],
                "familyName": employee["lastName"],
            },
            "suspended": employee["status"] != "Active",
            "emails": [
                {
                    "address": employee["homeEmail"],
                    "type": "home",
                },
                {
                    "address": employee["workEmail"],
                    "primary": True,
                },
            ],
            "relations": [
                {"value": employee["supervisorEmail"], "type": "manager"}
            ],
            "organizations": [
                {
                    "title": employee["jobTitle"],
                    "primary": True,
                    "department": employee["department"],
                }
            ],
            "externalIds": [{"value": employee["id"], "type": "organization"}],
        },
    }
    try:
        if dry_run:
            click.echo({"type": "dry_run_update_user", **update_kwargs})
        else:
            g.users().update(**update_kwargs).execute()
            click.echo({"type": "update_user", **update_kwargs})
    except HttpError as e:
        echo_http_error(e, **update_kwargs)

    
    


@cli.command()
@bamboo_subdomain
@bamboo_api_key
@google_admin
@google_credentials
@dry_run
def sync(**kwargs):
    _sync(**kwargs)


def _sync(bamboo_subdomain, bamboo_api_key, google_admin, google_credentials, dry_run):
    b = BambooSession(bamboo_subdomain, bamboo_api_key)
    g = create_directory_service(google_admin, google_credentials)

    since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
        "%Y-%m-%dT%H:%M:%S%z"
    )

    changes = b.get("/employees/changed", params={"type": "inserted", "since": since})
    for employee_id in changes["employees"] or []:
        employee = b.get(
            f"/employees/{employee_id}",
            params={
                "fields": ",".join(
                    [
                        "workEmail",
                        "preferredName",
                        "firstName",
                        "lastName",
                        "status",
                        "homeEmail",
                        "jobTitle",
                        "supervisorEmail",
                        "department",
                        "employmentType",
                        "id"
                    ]
                )
            },
        )

        insert_kwargs = {
            "body": {
                "primaryEmail": employee["workEmail"],
                "name": {
                    "givenName": employee["preferredName"] or employee["firstName"],
                    "familyName": employee["lastName"],
                },
                "suspended": employee["status"] != "Active",
                "password": secrets.token_urlsafe(32),
                "changePasswordAtNextLogin": True,
                "emails": [
                    {
                        "address": employee["homeEmail"],
                        "type": "home",
                    },
                    {
                        "address": employee["workEmail"],
                        "primary": True,
                    },
                ],
                "relations": [
                    {"value": employee["supervisorEmail"], "type": "manager"}
                ],
                "organizations": [
                    {
                        "title": employee["jobTitle"],
                        "primary": True,
                        "department": employee["department"],
                    }
                ],
                "externalIds": [{"value": employee["id"], "type": "organization"}],
                "orgUnitPath": "/Employees",
            }
        }
        try:
            if dry_run:
                click.echo({"type": "dry_run_insert_user", **insert_kwargs})
            else:
                g.users().insert(**insert_kwargs).execute()
                click.echo({"type": "insert_user", **insert_kwargs})
        except HttpError as e:
            echo_http_error(e, **insert_kwargs)
            continue

    changes = b.get("/employees/changed", params={"type": "updated", "since": since})
    for employee_id in changes["employees"] or []:
        employee = b.get(
            f"/employees/{employee_id}",
            params={
                "fields": ",".join(
                    [
                        "workEmail",
                        "preferredName",
                        "firstName",
                        "lastName",
                        "status",
                        "homeEmail",
                        "jobTitle",
                        "supervisorEmail",
                        "department",
                        "employmentType",
                        "id"
                    ]
                )
            },
        )

        try:
            user = get_user_by_external_id(g, employee["id"])
        except HttpError as e:
            echo_http_error(e)
            continue
        except NotFoundError as e:
            echo_not_found_error(e)
            continue

        # TODO/BUG status is not returned for api key owner
        if user["primaryEmail"] == google_admin:
            employee["status"] = "Active"
        
        # disable unsuspending
        if user["suspended"]:
            if dry_run:
                click.echo(
                    {
                        "type": "dry_run_skip_unsuspend_user",
                        "userKey": user["id"],
                        "reason": "User is currently suspended, and unsuspending is disabled.",
                    }
                )
            continue

        update_kwargs = {
            "userKey": user["id"],
            "body": {
                "primaryEmail": employee["workEmail"],
                "name": {
                    "givenName": employee["preferredName"] or employee["firstName"],
                    "familyName": employee["lastName"],
                },
                "suspended": employee["status"] != "Active",
                "emails": [
                    {
                        "address": employee["homeEmail"],
                        "type": "home",
                    },
                    {
                        "address": employee["workEmail"],
                        "primary": True,
                    },
                ],
                "relations": [
                    {"value": employee["supervisorEmail"], "type": "manager"}
                ],
                "organizations": [
                    {
                        "title": employee["jobTitle"],
                        "primary": True,
                        "department": employee["department"],
                    }
                ],
            },
        }
        try:
            if dry_run:
                click.echo({"type": "dry_run_update_user", **update_kwargs})
            else:
                g.users().update(**update_kwargs).execute()
                click.echo({"type": "update_user", **update_kwargs})
        except HttpError as e:
            echo_http_error(e, **update_kwargs)
            continue

    changes = b.get("/employees/changed", params={"type": "deleted", "since": since})
    for employee_id in changes["employees"] or []:
        try:
            user = get_user_by_external_id(g, employee_id)
        except HttpError as e:
            echo_http_error(e)
            continue
        except NotFoundError as e:
            echo_not_found_error(e)
            continue

        update_kwargs = {"userKey": user["id"], "body": {"suspended": True}}
        try:
            if dry_run:
                click.echo({"type": "dry_run_suspend_user", **update_kwargs})
            else:
                g.users().update(**update_kwargs).execute()
                click.echo({"type": "update_user", "action": "suspend", **update_kwargs})
        except HttpError as e:
            echo_http_error(e, **update_kwargs)


def get_user_by_external_id(g, external_id):
    list_kwargs = {
        "customer": "my_customer",
        "query": f"externalId={external_id}",
        "maxResults": 1,
    }
    res = g.users().list(**list_kwargs).execute()

    if "users" not in res:
        raise NotFoundError(f"User with external id {external_id} not found")

    return res["users"][0]


def echo_http_error(e, **kwargs):
    click.echo(
        {
            "type": "error",
            "status_code": e.status_code,
            "reason": e.reason,
            "error_details": e.error_details,
            **kwargs,
        }
    )


def echo_not_found_error(e):
    click.echo({"type": "error", "cause": str(e)})


class NotFoundError(Exception):
    pass


def lambda_handler(event, context):
    # Dry run for lambda needs to be configured via environment variable or event payload.
    # For now, assuming lambda always runs in non-dry-run mode.
    # If dry_run is needed for lambda, this needs adjustment.
    is_lambda_dry_run = os.environ.get("LAMBDA_DRY_RUN", "false").lower() == "true"

    _sync(
        get_secret(os.environ["BAMBOO_SUBDOMAIN"]),
        get_secret(os.environ["BAMBOO_API_KEY"]),
        get_secret(os.environ["GOOGLE_ADMIN"]),
        json.loads(get_secret(os.environ["GOOGLE_CREDENTIALS"])),
        dry_run=is_lambda_dry_run,  # Pass dry_run status to _sync
    )


def get_secret(id, parse_json=False):
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=id)
    return response["SecretString"]
