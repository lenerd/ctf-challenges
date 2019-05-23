// use actix_web::{server, App};
use crate::crypto::AuthEnc;
use actix_web::{http, server, App, Form, HttpRequest, HttpResponse, Responder};
use askama::Template;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use url::form_urlencoded::parse as urldecode;

const SITE_TITLE: &str = "3DES-HMAC";

fn load_cookie(req: &HttpRequest<AppState>) -> Option<HashMap<String, String>> {
    let cookie = req.cookie("auth")?;
    let mut ct = match base64::decode_config(cookie.value(), base64::URL_SAFE) {
        Ok(x) => x,
        Err(_) => return None,
    };
    let authenc = &req.state().authenc;
    let pt = match authenc.auth_decrypt(&mut ct) {
        Ok(pt) => pt,
        Err(_) => return None,
    };
    let decoded = urldecode(&pt);
    let mut map = HashMap::new();
    for (k, v) in decoded {
        map.insert(k.to_string(), v.to_string());
    }
    Some(map)
}

fn urlencode(map: &HashMap<String, String>) -> String {
    let mut iter = map.iter().map(|(k, v)| format!("{}={}", k, v));
    let mut result = String::new();

    match iter.next() {
        Some(x) => result = x,
        None => return result,
    }
    for x in iter {
        result += "&";
        result += &x;
    }
    result
}

fn bake_cookie(req: &HttpRequest<AppState>, map: &HashMap<String, String>) -> String {
    let pt = urlencode(map);
    let authenc = &req.state().authenc;
    let mut buffer = vec![0; AuthEnc::ciphertext_size(pt.as_bytes())];
    let ct = authenc.auth_encrypt(pt.as_bytes(), &mut buffer).unwrap();
    base64::encode_config(ct, base64::URL_SAFE)
}

fn redirect(path: &str) -> HttpResponse {
    HttpResponse::Found()
        .header(http::header::LOCATION, path)
        .finish()
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    title: &'a str,
    username: &'a str,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    title: &'a str,
}

#[derive(Template)]
#[template(path = "flag.html")]
struct FlagTemplate<'a> {
    title: &'a str,
    username: &'a str,
    flag: &'a str,
}

fn hn_index(req: &HttpRequest<AppState>) -> impl Responder {
    let cookie = match load_cookie(req) {
        Some(c) => c,
        None => return redirect("/login/"),
    };

    if !cookie.contains_key("username") {
        return redirect("/login/");
    }

    let body = IndexTemplate {
        title: SITE_TITLE,
        username: &cookie["username"],
    }
    .render()
    .unwrap();

    HttpResponse::Ok().content_type("text/html").body(body)
}

fn hn_login(_: &HttpRequest<AppState>) -> impl Responder {
    let body = LoginTemplate { title: SITE_TITLE }.render().unwrap();

    HttpResponse::Ok().content_type("text/html").body(body)
}

#[derive(Debug, Deserialize)]
struct LoginParams {
    username: String,
    password: String,
}

fn hn_login_post(req: (Form<LoginParams>, HttpRequest<AppState>)) -> HttpResponse {
    let (params, req) = req;
    if params.username.contains("almighty") {
        return redirect("/login/");
    }

    let mut cookie = HashMap::new();
    cookie.insert("username".to_owned(), params.username.clone());
    cookie.insert("is_admin".to_owned(), "lol no".to_owned());
    let cookie = bake_cookie(&req, &cookie);

    HttpResponse::Found()
        .header(http::header::LOCATION, "/")
        .cookie(http::Cookie::build("auth", cookie).path("/").finish())
        .finish()
}

fn hn_flag(req: &HttpRequest<AppState>) -> impl Responder {
    let cookie = match load_cookie(req) {
        Some(c) => c,
        None => return redirect("/login/"),
    };
    if cookie.contains_key("username")
        && cookie["username"] == "almighty_administrator"
        && cookie.contains_key("is_admin")
        && cookie["is_admin"] == "of_course"
    {
        let body = FlagTemplate {
            title: SITE_TITLE,
            username: &cookie["username"],
            flag: &req.state().flag,
        }
        .render()
        .unwrap();
        HttpResponse::Ok().body(body)
    } else {
        HttpResponse::Forbidden()
            .header(http::header::LOCATION, "/")
            .finish()
    }
}

#[derive(Clone)]
struct AppState {
    flag: String,
    authenc: AuthEnc,
}

fn make_app(flag: &String, authenc: &AuthEnc) -> App<AppState> {
    App::with_state(AppState {
        flag: flag.clone(),
        authenc: authenc.clone(),
    })
    .resource("/", |r| r.f(hn_index))
    .resource("/login/", |r| {
        r.method(http::Method::POST).with(hn_login_post);
        r.f(hn_login);
    })
    .resource("/flag/", |r| r.f(hn_flag))
    .handler(
        "/static",
        actix_web::fs::StaticFiles::new("static")
            .unwrap()
            .show_files_listing(),
    )
}

pub fn run() {
    let flag = fs::read_to_string("flag.txt").expect("Cannot read 'flag.txt'");
    let authenc = AuthEnc::new();
    server::new(move || make_app(&flag, &authenc))
        .bind("0.0.0.0:8080")
        .unwrap()
        .run();
}
