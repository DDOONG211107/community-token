const { Exception } = require("../module/Exception");
const wrapper = require("../module/wrapper");
const jwt = require("jsonwebtoken");
// checkIsLogin으로 이름 바꾸는게 낫다
// const checkIsLogin = (req, res, next) => {
//   const { accountIdx } = req.session;

//   if (!accountIdx) {
//     throw new Exception(403, "로그인 되어있지 않음");
//   }
//   next();
// };

const checkIsLogin = wrapper((req, res, next) => {
  const { token } = req.headers;
  // console.log("여기?");
  req.decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

  next();
});

module.exports = { checkIsLogin };
