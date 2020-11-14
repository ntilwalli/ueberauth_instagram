defmodule Ueberauth.Strategy.Instagram do
  @moduledoc """
  Instagram Strategy for Überauth.
  """

  use Ueberauth.Strategy, default_scope: "user_profile",
                          uid_field: :id,
                          allowed_request_params: [
                            :auth_type,
                            :scope
                          ]


  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles initial request for Instagram authentication.
  """
  def handle_request!(conn) do
    allowed_params = conn
     |> option(:allowed_request_params)
     |> Enum.map(&to_string/1)

    authorize_url = conn.params
      |> maybe_replace_param(conn, "scope", :default_scope)
      |> Enum.filter(fn {k,_v} -> Enum.member?(allowed_params, k) end)
      |> Enum.map(fn {k,v} -> {String.to_existing_atom(k), v} end)
      |> Keyword.put(:redirect_uri, callback_url(conn))
      |> Ueberauth.Strategy.Instagram.OAuth.authorize_url!

    redirect!(conn, authorize_url)
  end

  @doc """
  Handles the callback from Instagram.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = [redirect_uri: callback_url(conn)]
    token = Ueberauth.Strategy.Instagram.OAuth.get_token!([code: code], opts).token

    if token.access_token == nil do
      err = token.other_params["error"]
      desc = token.other_params["error_description"]
      set_errors!(conn, [error(err, desc)])
    else
      %{"access_token" => ac, "user_id" => user_id} = Jason.decode!(token.access_token)
      result =
        case :hackney.request(:get, "https://graph.instagram.com/#{user_id}?fields=id,username&access_token=#{ac}", [], "", []) do
          {:ok, ref} when is_reference(ref) ->
            :hackney.body(ref)
          {:ok, status, headers, ref} when is_reference(ref) ->
            :hackney.body(ref)
          {:ok, _status, _headers, body} when is_binary(body) ->
            {:ok, body}
          out -> out
        end

      case result do
        {:error, reason} ->
          set_errors!(conn, [error(reason, reason)])
        {:ok, body} ->
          %{"id" => _uid, "username" => _username} = result = Jason.decode!(body)
          fetch_user(conn, result)
      end
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:instagram_user, nil)
    |> put_private(:instagram_token, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.instagram_user[uid_field]
  end

  @doc """
  Includes the credentials from the instagram response.
  """
  def credentials(conn) do
    %Credentials{}
  end

  @doc """
  Fetches the fields to populate the info section of the
  `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.instagram_user
    %Info{
      nickname: user["username"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from
  the instagram callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: conn.private.instagram_user
    }
  end

  defp fetch_user(conn, user) do
    put_private(conn, :instagram_user, user)
  end

  defp option(conn, key) do
    default = Dict.get(default_options, key)

    conn
    |> options
    |> Dict.get(key, default)
  end
  defp option(nil, conn, key), do: option(conn, key)
  defp option(value, _conn, _key), do: value

  defp maybe_replace_param(params, conn, name, config_key) do
    if params[name] do
      params
    else
      Map.put(
        params,
        name,
        option(params[name], conn, config_key)
      )
    end
  end
end
