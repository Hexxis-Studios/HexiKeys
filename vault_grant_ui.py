"""Owner-facing dialogs for creating and revoking HexiGrid field grants.

These dialogs accept only a nonsecret scope recipe. They never read or render
the selected field value; the reference module alone resolves a value later.
"""

import json
import time
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk

import vault_references as references


RECIPE_KEYS = frozenset({
    "version", "connectorId", "capabilityId", "taskId", "origin",
    "pathPrefix", "methods", "header", "prefix",
})
DEFAULT_TTL_SECONDS = 60 * 60


def _parse_scope_recipe(text):
    """Parse a strict, nonsecret recipe object, rejecting duplicate/extra keys."""
    if not isinstance(text, str) or len(text.encode("utf-8")) > 16_384:
        raise ValueError("Paste a valid HexiGrid scope recipe (up to 16 KB).")

    def object_without_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("The scope recipe contains a duplicate property.")
            result[key] = value
        return result

    try:
        recipe = json.loads(text, object_pairs_hook=object_without_duplicates)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("The scope recipe is not valid JSON.") from exc
    if not isinstance(recipe, dict) or set(recipe) != RECIPE_KEYS:
        raise ValueError("The recipe must contain exactly the documented scope properties.")
    if type(recipe.get("version")) is not int or recipe["version"] != 1:
        raise ValueError("This scope recipe version is not supported.")
    for key in ("connectorId", "capabilityId", "taskId", "origin", "pathPrefix", "header", "prefix"):
        if not isinstance(recipe.get(key), str):
            raise ValueError(f"The scope recipe property {key} must be text.")
    methods = recipe.get("methods")
    if not isinstance(methods, list) or not methods or any(not isinstance(method, str) for method in methods):
        raise ValueError("The scope recipe must include one or more HTTP methods.")
    if any(ord(char) < 0x20 or ord(char) == 0x7f for key in ("connectorId", "capabilityId", "taskId", "origin", "pathPrefix", "header", "prefix") for char in recipe[key]):
        raise ValueError("The scope recipe cannot contain control characters.")
    return recipe


def _commit_if_current(snapshot, get_vault, commit_vault, candidate):
    """Refuse to overwrite vault state that changed or was locked meanwhile."""
    try:
        current = get_vault()
    except Exception as exc:
        raise RuntimeError("The vault is no longer available. Unlock it and try again.") from exc
    if current is not snapshot:
        raise RuntimeError("The vault changed while this dialog was open. Reopen it and review the current item.")
    try:
        result = commit_vault(candidate)
    except Exception as exc:
        raise RuntimeError("The encrypted vault could not be saved. Your current vault was left unchanged.") from exc
    if isinstance(result, BaseException):
        raise RuntimeError("The encrypted vault could not be saved. Your current vault was left unchanged.")
    return result


def _entry_choices(vault):
    entries = vault.get("entries") if isinstance(vault, dict) else None
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict) and isinstance(entry.get("id"), str)]


def _field_choices(entry):
    fields = entry.get("fields") if isinstance(entry, dict) else None
    if not isinstance(fields, list):
        return []
    result = []
    for index, field in enumerate(fields):
        if isinstance(field, dict) and isinstance(field.get("label"), str):
            # Deliberately retain only label and index; never copy a value into UI state.
            result.append((index, field["label"] or "Unnamed field"))
    return result


def _scope_summary(recipe, item_name, field_label, ttl_hours, max_uses):
    methods = ", ".join(method.upper() for method in recipe["methods"])
    prefix = recipe["prefix"]
    header_line = f"{recipe['header']}: {prefix}[credential]" if prefix else f"{recipe['header']}: [credential]"
    return (
        "Create this HexiGrid credential reference?\n\n"
        f"Vault item: {item_name}\nField: {field_label}\n"
        f"Connector: {recipe['connectorId']}\nCapability: {recipe['capabilityId']}\nTask: {recipe['taskId']}\n"
        f"Destination: {recipe['origin']}{recipe['pathPrefix']}\nMethods: {methods}\n"
        f"Credential header: {header_line}\nExpires in: {ttl_hours:g} hour(s)\nMaximum uses: {max_uses}\n\n"
        "The credential value stays in HexiKeys."
    )


def show_grant_dialog(parent, *, get_vault, commit_vault, entry_id=None, field_index=None):
    """Open an owner-reviewed grant dialog; return the committed grant ID or None."""
    try:
        snapshot = get_vault()
    except Exception:
        messagebox.showerror("HexiGrid reference", "The vault is unavailable. Unlock it and try again.", parent=parent)
        return None
    if not isinstance(snapshot, dict):
        messagebox.showerror("HexiGrid reference", "The vault is unavailable. Unlock it and try again.", parent=parent)
        return None
    entries = _entry_choices(snapshot)
    if not entries:
        messagebox.showinfo("HexiGrid reference", "Add a vault item with a field before creating a reference.", parent=parent)
        return None

    dialog = tk.Toplevel(parent)
    dialog.title("Share one field with HexiGrid")
    dialog.transient(parent)
    dialog.grab_set()
    dialog.geometry("680x650")
    result = {"grant_id": None}

    body = ttk.Frame(dialog, padding=16)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text="Share one field with HexiGrid", font=("Segoe UI", 15, "bold")).pack(anchor="w")
    ttk.Label(body, text="Paste a nonsecret scope recipe, choose one field, then review the exact scope before saving.", wraplength=630).pack(anchor="w", pady=(4, 12))

    entry_names = [str(entry.get("title") or "Untitled item") for entry in entries]
    entry_var = tk.StringVar(value="")
    ttk.Label(body, text="Vault item").pack(anchor="w")
    entry_box = ttk.Combobox(body, textvariable=entry_var, values=entry_names, state="readonly")
    entry_box.pack(fill="x", pady=(2, 8))
    field_var = tk.StringVar(value="")
    ttk.Label(body, text="Field (value remains hidden)").pack(anchor="w")
    field_box = ttk.Combobox(body, textvariable=field_var, state="readonly")
    field_box.pack(fill="x", pady=(2, 10))

    def update_fields(_event=None, preferred_index=None):
        index = entry_box.current()
        if not 0 <= index < len(entries):
            field_box.configure(values=())
            field_box.set("")
            return
        choices = _field_choices(entries[index])
        field_box.configure(values=[label for _field_index, label in choices])
        field_box.set("")
        if preferred_index is not None:
            for choice_index, (actual_index, _label) in enumerate(choices):
                if actual_index == preferred_index:
                    field_box.current(choice_index)
                    break

    entry_box.bind("<<ComboboxSelected>>", update_fields)
    preferred_entry = next((i for i, entry in enumerate(entries) if entry_id is not None and entry.get("id") == entry_id), None)
    if preferred_entry is None:
        entry_box.current(0)
        update_fields()
    else:
        entry_box.current(preferred_entry)
        update_fields(preferred_index=field_index)

    ttk.Label(body, text="HexiGrid scope recipe (JSON)").pack(anchor="w")
    recipe_text = tk.Text(body, height=10, wrap="word", undo=True)
    recipe_text.pack(fill="both", expand=True, pady=(2, 8))
    ttk.Label(body, text="Recipe keys: version, connectorId, capabilityId, taskId, origin, pathPrefix, methods, header, prefix. No credential values.", wraplength=630).pack(anchor="w")

    options = ttk.Frame(body)
    options.pack(fill="x", pady=(12, 8))
    ttk.Label(options, text="Expiry (hours, max 720)").grid(row=0, column=0, sticky="w")
    ttl_var = tk.StringVar(value="1")
    ttk.Spinbox(options, from_=1, to=720, increment=1, textvariable=ttl_var, width=8).grid(row=1, column=0, sticky="w", padx=(0, 24))
    ttk.Label(options, text="Maximum uses (max 1000)").grid(row=0, column=1, sticky="w")
    uses_var = tk.StringVar(value="1")
    ttk.Spinbox(options, from_=1, to=references.MAX_USES, increment=1, textvariable=uses_var, width=8).grid(row=1, column=1, sticky="w")

    buttons = ttk.Frame(body)
    buttons.pack(fill="x", pady=(8, 0))
    ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right")

    def create():
        selected_entry_index = entry_box.current()
        if not 0 <= selected_entry_index < len(entries):
            messagebox.showerror("HexiGrid reference", "Choose a vault item.", parent=dialog)
            return
        entry = entries[selected_entry_index]
        choices = _field_choices(entry)
        selected_field_choice = field_box.current()
        if not 0 <= selected_field_choice < len(choices):
            messagebox.showerror("HexiGrid reference", "Choose one field.", parent=dialog)
            return
        actual_field_index, field_label = choices[selected_field_choice]
        try:
            recipe = _parse_scope_recipe(recipe_text.get("1.0", "end-1c"))
            ttl_hours = int(ttl_var.get())
            max_uses = int(uses_var.get())
            if not 1 <= ttl_hours <= 720:
                raise ValueError("Expiry must be between 1 and 720 hours.")
            if not 1 <= max_uses <= references.MAX_USES:
                raise ValueError(f"Maximum uses must be between 1 and {references.MAX_USES}.")
            now = int(time.time())
            expires_at = now + ttl_hours * 60 * 60
            summary = _scope_summary(recipe, str(entry.get("title") or "Untitled item"), field_label, ttl_hours, max_uses)
        except (ValueError, TypeError) as exc:
            messagebox.showerror("HexiGrid reference", str(exc), parent=dialog)
            return
        if not messagebox.askyesno("Review credential reference", summary, parent=dialog):
            return
        try:
            candidate, grant_id = references.create_reference_grant(
                snapshot,
                entry_id=entry.get("id"),
                field_index=actual_field_index,
                connector_id=recipe["connectorId"],
                capability_id=recipe["capabilityId"],
                task_id=recipe["taskId"],
                origin=recipe["origin"],
                path_prefix=recipe["pathPrefix"],
                methods=recipe["methods"],
                header=recipe["header"],
                prefix=recipe["prefix"],
                expires_at=expires_at,
                max_uses=max_uses,
                now=now,
            )
            _commit_if_current(snapshot, get_vault, commit_vault, candidate)
        except ValueError as exc:
            messagebox.showerror("HexiGrid reference", str(exc), parent=dialog)
            return
        except RuntimeError as exc:
            messagebox.showerror("HexiGrid reference", str(exc), parent=dialog)
            return
        except Exception:
            messagebox.showerror("HexiGrid reference", "The reference could not be saved. The vault was not changed.", parent=dialog)
            return
        result["grant_id"] = grant_id
        dialog.destroy()
        _show_copyable_grant_id(parent, grant_id)

    ttk.Button(buttons, text="Review and create", command=create).pack(side="right", padx=(0, 8))
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.wait_window()
    return result["grant_id"]


def _show_copyable_grant_id(parent, grant_id):
    dialog = tk.Toplevel(parent)
    dialog.title("Reference created")
    dialog.transient(parent)
    dialog.grab_set()
    frame = ttk.Frame(dialog, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="Reference created and saved", font=("Segoe UI", 13, "bold")).pack(anchor="w")
    ttk.Label(frame, text="Copy this opaque reference ID if your HexiGrid setup asks for it. It does not contain the credential.", wraplength=460).pack(anchor="w", pady=(6, 10))
    value = tk.StringVar(value=grant_id)
    field = ttk.Entry(frame, textvariable=value, state="readonly", width=40)
    field.pack(fill="x")

    def copy_id():
        dialog.clipboard_clear()
        dialog.clipboard_append(grant_id)
        messagebox.showinfo("Reference ID", "Reference ID copied.", parent=dialog)

    buttons = ttk.Frame(frame)
    buttons.pack(fill="x", pady=(12, 0))
    ttk.Button(buttons, text="Copy ID", command=copy_id).pack(side="right", padx=(0, 8))
    ttk.Button(buttons, text="Close", command=dialog.destroy).pack(side="right")
    field.selection_range(0, "end")
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.wait_window()


def show_grants_dialog(parent, *, get_vault, commit_vault):
    """Show display-safe grant metadata and allow encrypted-state revocation."""
    try:
        snapshot = get_vault()
        rows = references.public_reference_grants(snapshot)
    except Exception:
        messagebox.showerror("HexiGrid references", "Grant details are unavailable. Unlock the vault and try again.", parent=parent)
        return None
    if not isinstance(snapshot, dict):
        messagebox.showerror("HexiGrid references", "Grant details are unavailable. Unlock the vault and try again.", parent=parent)
        return None

    dialog = tk.Toplevel(parent)
    dialog.title("HexiGrid references")
    dialog.transient(parent)
    dialog.grab_set()
    dialog.geometry("1000x430")
    frame = ttk.Frame(dialog, padding=12)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="HexiGrid references", font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(0, 8))
    columns = ("item", "field", "connector", "capability", "task", "destination", "methods", "uses", "expiry", "status")
    tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
    headings = {
        "item": "Vault item", "field": "Field", "connector": "Connector", "capability": "Capability", "task": "Task",
        "destination": "Origin and path", "methods": "Methods", "uses": "Uses", "expiry": "Expires", "status": "Status",
    }
    widths = {"item": 115, "field": 90, "connector": 90, "capability": 100, "task": 100, "destination": 190, "methods": 70, "uses": 70, "expiry": 135, "status": 90}
    for name in columns:
        tree.heading(name, text=headings[name])
        tree.column(name, width=widths[name], minwidth=55, stretch=name in {"destination", "item", "field"})
    tree.pack(fill="both", expand=True)
    id_by_iid = {}
    now = int(time.time())
    for index, grant in enumerate(rows):
        grant_id = grant.get("id")
        expires_at = grant.get("expiresAt")
        max_uses = grant.get("maxUses")
        uses = grant.get("uses")
        revoked = grant.get("revoked") is True
        expired = type(expires_at) is int and expires_at <= now
        spent = type(max_uses) is int and type(uses) is int and uses >= max_uses
        status = "Revoked" if revoked else "Expired" if expired else "Used up" if spent else "Active"
        if type(expires_at) is int:
            expiry = datetime.fromtimestamp(expires_at).astimezone().strftime("%Y-%m-%d %H:%M")
        else:
            expiry = "Unavailable"
        use_text = f"{uses}/{max_uses}" if type(uses) is int and type(max_uses) is int else "Unavailable"
        destination = f"{grant.get('origin', '')}{grant.get('pathPrefix', '')}"[:220]
        values = (
            str(grant.get("itemName", "Unavailable"))[:128], str(grant.get("fieldLabel", "Unavailable"))[:128],
            str(grant.get("connectorId", ""))[:63], str(grant.get("capabilityId", ""))[:63],
            str(grant.get("taskId", ""))[:128], destination, ", ".join(grant.get("methods", [])), use_text, expiry, status,
        )
        iid = f"grant-row-{index}"
        tree.insert("", "end", iid=iid, values=values)
        if isinstance(grant_id, str):
            id_by_iid[iid] = grant_id
    if not rows:
        ttk.Label(frame, text="No HexiGrid references have been created.").pack(anchor="w", pady=8)

    footer = ttk.Frame(frame)
    footer.pack(fill="x", pady=(10, 0))
    ttk.Button(footer, text="Close", command=dialog.destroy).pack(side="right")

    def revoke_selected():
        nonlocal snapshot
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Revoke reference", "Select a reference first.", parent=dialog)
            return
        grant_id = id_by_iid.get(selected[0])
        if not grant_id:
            return
        values = tree.item(selected[0], "values")
        status = values[-1]
        if status == "Revoked":
            messagebox.showinfo("Revoke reference", "This reference is already revoked.", parent=dialog)
            return
        summary = (
            f"Revoke the reference for {values[0]} / {values[1]}?\n\n"
            f"Connector: {values[2]}\nCapability: {values[3]}\nTask: {values[4]}\nDestination: {values[5]}\n\n"
            "HexiGrid will no longer be able to use this field through this reference."
        )
        if not messagebox.askyesno("Review revocation", summary, parent=dialog):
            return
        try:
            candidate = references.revoke_reference_grant(snapshot, grant_id)
            _commit_if_current(snapshot, get_vault, commit_vault, candidate)
        except ValueError as exc:
            messagebox.showerror("Reference not revoked", str(exc), parent=dialog)
            return
        except RuntimeError as exc:
            messagebox.showerror("Reference not revoked", str(exc), parent=dialog)
            return
        except Exception:
            messagebox.showerror("Reference not revoked", "The encrypted vault could not be saved. The reference remains unchanged.", parent=dialog)
            return
        snapshot = candidate
        values = list(values)
        values[-1] = "Revoked"
        tree.item(selected[0], values=values)
        messagebox.showinfo("Reference revoked", "The encrypted vault saved the revocation.", parent=dialog)

    ttk.Button(footer, text="Revoke selected", command=revoke_selected).pack(side="right", padx=(0, 8))
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.wait_window()
    return None
