const express = require('express')
const jwt = require('jsonwebtoken')
const app = express()
const crypto = require('crypto')
const { fetch } = require('undici')

const log = console.log

// --- SETTINGS

  // 서비스 포트
  const PORT = 3000

  // 클라이언트 ID: 발급은 https://center.gbsw.hs.kr 에서 로그인 후 신규등록!
  const CLIENT_ID = 'f0c1f28d-6f92-4372-ad29-08fa835e56ac'

  // 받아올 개인정보 목록: 사용 가능한 목록 참고 -> https://github.com/redarchive/center-oidc/wiki/%ED%86%B5%ED%95%A9%EB%A1%9C%EA%B7%B8%EC%9D%B8%EC%8B%9C%EC%8A%A4%ED%85%9C-%EC%82%AC%EC%9A%A9%EB%B2%95#scope-%ED%85%8C%EC%9D%B4%EB%B8%94
  const SCOPES = 'openid real_name class_info'

  // 리다이렉트 주소: 등록시 입력한 주소 사용!
  const REDIRECT_URI = `http://localhost:${PORT}/callback`

  // 서버 검증용 퍼블릭키 주소
  const PUBKEY_URL =
    'https://center.gbsw.hs.kr/publickey.pub'

  // 서버 검증용 토큰 생성자 정보
  const ISSUER =
    'https://center.gbsw.hs.kr'
  
  // 로그인 주소
  const LOGIN_URL = (state, nonce) =>
    'https://center.gbsw.hs.kr/login' +
      `?client_id=${CLIENT_ID}` +
      `&redirect_uri=${REDIRECT_URI}` +
      `&scope=${SCOPES}` +
      `&state=${state}` +
      `&nonce=${nonce}` +
      `&response_type=id_token`


// ---

// 토큰 위변조 방지 STATE, NONCE 스토리지
const nonces = new Map()


app.use((req, res, next) => {
  log(`브라우저가 "${req.path}" 로 접속했습니다`)
  next()
})


app.get('/', (req, res) => {
  const nonce = crypto.randomBytes(10).toString('hex')
  log(`ㄴ 새로운 NONCE를 생성했습니다: ${nonce}`)

  const state = crypto.randomBytes(10).toString('hex')
  log(`ㄴ 새로운 STATE를 생성했습니다: ${state}`)
  
  nonces.set(state, nonce)
  setInterval(() => nonces.delete(state), 60 * 1000)
  
  res.send(`<a href="${LOGIN_URL(state, nonce)}">login</a>`)
  log('ㄴ 로그인 버튼을 표시했습니다')
})


app.get('/callback', async (req, res) => {
  log(`ㄴ 전달받은 id_token = "${req.query.id_token}"`)
  log(`ㄴ 전달받은 state = "${req.query.state}"`)

  if (!nonces.has(req.query.state)) {
    log('ㄴ 알수없는 state입니다. 위변조 위험이 있습니다')
    res.send('FAILED')
    return
  }
  log('ㄴ STATE 검사를 통과하였습니다')

  const pubkey = await fetch(PUBKEY_URL).then((res) => res.text())
  log(`ㄴ 통합로그인시스템 서버에서 퍼블릭키를 받아왔습니다:\n${pubkey}`)

  const nonce = nonces.get(req.query.state)
  nonces.delete(req.query.state)

  try {
    const verified = jwt.verify(req.query.id_token, pubkey, {
      algorithms: ['ES256'],
      audience: CLIENT_ID,
      issuer: ISSUER,
      nonce: nonce
    })

    log(`ㄴ id_token을 JWT로 검증 한 결과:`, verified)

    res.set('Content-Type', 'text/plain')
    res.send(`LOGIN RESULT:\n${JSON.stringify(verified, null, 2)}`)
  } catch (e) {
    log(`ㄴ 토큰 검증에 실패하였습니다: ${e.message}`)
    res.send('FAILED')
  }
})


app.listen(PORT, () =>
  log(`서버가 실행되었습니다 : http://localhost:${PORT}`))
