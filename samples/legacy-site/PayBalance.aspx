<%@ Page Language="C#" CodeBehind="PayBalance.aspx.cs" %>
<form runat="server">
  <!-- Server-side Braintree: the card number reaches our code-behind. -->
  <asp:TextBox ID="txtCardNo" runat="server" />
  <asp:TextBox ID="txtSecurityCode" runat="server" />
  <asp:Button ID="btnSubmit" runat="server" Text="Pay" />
</form>
