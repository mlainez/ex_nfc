# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.Application do
  @moduledoc false

  use Application

  @impl Application
  def start(_type, _args) do
    controller_opts = Application.get_env(:ex_nfc, :controller, [])

    children = [
      {Registry, keys: :duplicate, name: ExNfc.Registry},
      {ExNfc.Controller, controller_opts}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: ExNfc.Supervisor)
  end
end
